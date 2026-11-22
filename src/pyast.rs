//! Python source analysis. loki.py parses Python with CPython's `ast` and
//! `tokenize`; what parses (and how a syntax error reads) depends on that
//! interpreter, so the Rust engine asks CPython for the tree and tokens and
//! ports every rule that walks them.

use crate::CheckError;
use crate::text::{Text, blank};
use crate::{jsrules, langrules, py};
use regex::Regex;
use serde_json::{Value, json};
use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::{Arc, LazyLock, Mutex};

pub const LOKI_PYTHON_ENV: &str = "ULTRON_LOKI_PYTHON";

const HELPER: &str = r#"
import ast, json, sys, tokenize, io, warnings
sys.setrecursionlimit(20000)

def text(value):
    return value.encode("utf-8", "surrogatepass").decode("utf-8", "replace")

def flatten(tree):
    nodes = []
    def conv(value):
        if isinstance(value, ast.AST):
            index = len(nodes)
            nodes.append(None)
            fields = {}
            for name in value._fields:
                item = getattr(value, name, None)
                if isinstance(value, ast.Constant) and name == "value":
                    fields[name] = {"%": [type(item).__name__, ascii(item), text(item) if isinstance(item, str) else None]}
                else:
                    fields[name] = conv(item)
            position = None
            if "lineno" in value._attributes:
                position = [getattr(value, key, None) for key in ("lineno", "col_offset", "end_lineno", "end_col_offset")]
            func = ast.unparse(value.func) if isinstance(value, ast.Call) else None
            nodes[index] = [type(value).__name__, fields, position, func]
            return {"$": index}
        if isinstance(value, list):
            return [conv(item) for item in value]
        if isinstance(value, str):
            return text(value)
        if value is None or isinstance(value, (bool, int)):
            return value
        return {"%": [type(value).__name__, ascii(value), None]}
    conv(tree)
    return nodes

def answer(request):
    source = request["text"]
    if request["op"] == "tokens":
        found = []
        try:
            for token in tokenize.generate_tokens(io.StringIO(source).readline):
                if token.type in (tokenize.COMMENT, tokenize.STRING):
                    found.append([token.type == tokenize.COMMENT, *token.start, *token.end, token.string])
        except (tokenize.TokenError, SyntaxError, IndentationError):
            pass
        return {"tokens": found}
    with warnings.catch_warnings(record=True) as caught:
        try:
            if request.get("filename") is None:
                tree = ast.parse(source)
            else:
                tree = ast.parse(source, filename=request["filename"])
        except (SyntaxError, ValueError) as error:
            tree = None
            failure = str(error)
    shown = [warnings.formatwarning(w.message, w.category, w.filename, w.lineno, w.line) for w in caught]
    if tree is None:
        return {"error": failure, "warnings": shown}
    return {"nodes": flatten(tree), "warnings": shown}

requests = json.loads(sys.stdin.buffer.read().decode("utf-8"))
replies = []
for request in requests:
    try:
        replies.append(answer(request))
    except Exception as error:
        replies.append({"fatal": [type(error).__name__, str(error)]})
print(json.dumps({"stdlib": sorted(sys.stdlib_module_names), "builtin": sorted(sys.builtin_module_names), "replies": replies}))
"#;

/// A field value of a parsed node.
#[derive(Debug, Clone)]
pub enum F {
    Node(usize),
    List(Vec<F>),
    Str(String),
    Int(i64),
    Bool(bool),
    Null,
    Const(Const),
}

/// A `Constant` value: its type name, `ascii()` and text when it is a `str`.
#[derive(Debug, Clone)]
pub struct Const {
    pub kind: String,
    pub repr: String,
    pub text: Option<String>,
}

#[derive(Debug)]
pub struct Node {
    pub kind: String,
    pub fields: Vec<(String, F)>,
    pub position: Option<[Option<i64>; 4]>,
    pub func: Option<String>,
}

/// A parsed module; node 0 is the root.
#[derive(Debug)]
pub struct Tree {
    pub nodes: Vec<Node>,
}

fn field(value: &Value) -> F {
    match value {
        Value::Null => F::Null,
        Value::Bool(b) => F::Bool(*b),
        Value::Number(n) => F::Int(n.as_i64().unwrap_or(0)),
        Value::String(s) => F::Str(s.clone()),
        Value::Array(items) => F::List(items.iter().map(field).collect()),
        Value::Object(map) => {
            if let Some(index) = map.get("$").and_then(Value::as_u64) {
                return F::Node(index as usize);
            }
            let parts = map.get("%").and_then(Value::as_array);
            let part = |i: usize| parts.and_then(|p| p.get(i));
            F::Const(Const {
                kind: part(0).and_then(Value::as_str).unwrap_or("").to_string(),
                repr: part(1).and_then(Value::as_str).unwrap_or("").to_string(),
                text: part(2).and_then(Value::as_str).map(String::from),
            })
        }
    }
}

impl Tree {
    fn from_wire(nodes: &[Value]) -> Tree {
        let nodes = nodes
            .iter()
            .map(|item| {
                let kind = item[0].as_str().unwrap_or("").to_string();
                let fields = item[1]
                    .as_object()
                    .map(|m| m.iter().map(|(k, v)| (k.clone(), field(v))).collect())
                    .unwrap_or_default();
                let position = item[2].as_array().map(|p| {
                    let at = |i: usize| p.get(i).and_then(Value::as_i64);
                    [at(0), at(1), at(2), at(3)]
                });
                Node {
                    kind,
                    fields,
                    position,
                    func: item[3].as_str().map(String::from),
                }
            })
            .collect();
        Tree { nodes }
    }

    pub fn kind(&self, id: usize) -> &str {
        &self.nodes[id].kind
    }

    pub fn is(&self, id: usize, kinds: &[&str]) -> bool {
        kinds.contains(&self.kind(id))
    }

    pub fn get(&self, id: usize, name: &str) -> &F {
        static NULL: F = F::Null;
        self.nodes[id]
            .fields
            .iter()
            .find(|(k, _)| k == name)
            .map_or(&NULL, |(_, v)| v)
    }

    pub fn node(&self, id: usize, name: &str) -> Option<usize> {
        match self.get(id, name) {
            F::Node(child) => Some(*child),
            _ => None,
        }
    }

    pub fn list(&self, id: usize, name: &str) -> Vec<usize> {
        match self.get(id, name) {
            F::List(items) => items
                .iter()
                .filter_map(|i| if let F::Node(n) = i { Some(*n) } else { None })
                .collect(),
            _ => vec![],
        }
    }

    pub fn str(&self, id: usize, name: &str) -> Option<&str> {
        match self.get(id, name) {
            F::Str(s) => Some(s),
            _ => None,
        }
    }

    pub fn line(&self, id: usize) -> i64 {
        self.nodes[id].position.and_then(|p| p[0]).unwrap_or(0)
    }

    pub fn col(&self, id: usize) -> i64 {
        self.nodes[id].position.and_then(|p| p[1]).unwrap_or(0)
    }

    pub fn end_line(&self, id: usize) -> Option<i64> {
        self.nodes[id].position.and_then(|p| p[2])
    }

    pub fn constant(&self, id: usize) -> Option<&Const> {
        if self.kind(id) != "Constant" {
            return None;
        }
        match self.get(id, "value") {
            F::Const(c) => Some(c),
            _ => None,
        }
    }

    pub fn constant_str(&self, id: usize) -> Option<&str> {
        self.constant(id)
            .filter(|c| c.kind == "str")
            .and_then(|c| c.text.as_deref())
    }

    /// `ast.unparse(node.func)` for a `Call`.
    pub fn func_text(&self, id: usize) -> &str {
        self.nodes[id].func.as_deref().unwrap_or("")
    }

    /// `ast.iter_child_nodes`.
    pub fn children(&self, id: usize) -> Vec<usize> {
        let mut out = Vec::new();
        for (_, value) in &self.nodes[id].fields {
            match value {
                F::Node(n) => out.push(*n),
                F::List(items) => out.extend(
                    items
                        .iter()
                        .filter_map(|i| if let F::Node(n) = i { Some(*n) } else { None }),
                ),
                _ => {}
            }
        }
        out
    }

    /// `ast.walk`: breadth first, the node itself first.
    pub fn walk(&self, id: usize) -> Vec<usize> {
        let mut order = Vec::new();
        let mut todo = VecDeque::from([id]);
        while let Some(node) = todo.pop_front() {
            todo.extend(self.children(node));
            order.push(node);
        }
        order
    }

    /// `ast.dump(node)`: structure without positions.
    pub fn dump(&self, id: usize) -> String {
        let mut out = String::new();
        self.dump_into(&F::Node(id), &mut out);
        out
    }

    fn dump_into(&self, value: &F, out: &mut String) {
        match value {
            F::Node(n) => {
                out.push_str(&self.nodes[*n].kind);
                out.push('(');
                for (name, item) in &self.nodes[*n].fields {
                    out.push_str(name);
                    out.push('=');
                    self.dump_into(item, out);
                    out.push(',');
                }
                out.push(')');
            }
            F::List(items) => {
                out.push('[');
                for item in items {
                    self.dump_into(item, out);
                    out.push(',');
                }
                out.push(']');
            }
            F::Str(s) => out.push_str(&format!("{s:?}")),
            F::Int(i) => out.push_str(&i.to_string()),
            F::Bool(b) => out.push_str(if *b { "True" } else { "False" }),
            F::Null => out.push_str("None"),
            F::Const(c) => out.push_str(&format!("{}:{}", c.kind, c.repr)),
        }
    }
}

/// What CPython answered for one source text.
#[derive(Debug, Clone)]
pub enum Parsed {
    Tree(Arc<Tree>),
    Error(String),
}

type Key = (&'static str, Option<String>, String);

struct State {
    parsed: HashMap<Key, Parsed>,
    /// What CPython printed to stderr while parsing (SyntaxWarnings), per source.
    warned: HashMap<Key, String>,
    /// `content_memo`: per-file analyses loki.py computes once per process.
    memo: HashSet<(&'static str, String, String)>,
    tokens: HashMap<String, Arc<Vec<Value>>>,
    stdlib: Option<Arc<(HashSet<String>, HashSet<String>)>>,
}

static STATE: LazyLock<Mutex<State>> = LazyLock::new(|| {
    Mutex::new(State {
        parsed: HashMap::new(),
        warned: HashMap::new(),
        memo: HashSet::new(),
        tokens: HashMap::new(),
        stdlib: None,
    })
});

/// The interpreter that parses Python for Loki (`findPython`: `ULTRON_LOKI_PYTHON`, trimmed), else the kernel's.
pub(crate) fn interpreter() -> String {
    std::env::var(LOKI_PYTHON_ENV)
        .ok()
        .map(|p| p.trim().to_string())
        .filter(|p| !p.is_empty())
        .unwrap_or_else(crate::compat::python_interpreter)
}

fn unavailable(message: impl Into<String>) -> CheckError {
    CheckError::Guard("PythonUnavailable".into(), message.into())
}

fn missing_requests(state: &State, requests: Vec<(Key, bool)>) -> Vec<(Key, bool)> {
    let mut wanted: Vec<(Key, bool)> = Vec::new();
    for (key, tokens) in requests {
        let known = if tokens {
            state.tokens.contains_key(&key.2)
        } else {
            state.parsed.contains_key(&key)
        };
        if !known && !wanted.contains(&(key.clone(), tokens)) {
            wanted.push((key, tokens));
        }
    }
    wanted
}

fn run_helper(wanted: &[(Key, bool)]) -> Result<Value, CheckError> {
    let payload: Vec<Value> = wanted
        .iter()
        .map(|((_, filename, text), tokens)| {
            json!({"op": if *tokens { "tokens" } else { "parse" }, "filename": filename, "text": text})
        })
        .collect();
    let python = interpreter();
    let mut child = Command::new(&python)
        .args(["-I", "-c", HELPER])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| unavailable(format!("{python}: {e}")))?;
    let input = serde_json::to_vec(&payload).map_err(|e| unavailable(e.to_string()))?;
    let mut stdin = child.stdin.take().ok_or_else(|| unavailable("no stdin"))?;
    let writer = std::thread::spawn(move || stdin.write_all(&input));
    let output = child.wait_with_output().map_err(|e| unavailable(e.to_string()))?;
    let _ = writer.join();
    if !output.status.success() {
        return Err(unavailable(String::from_utf8_lossy(&output.stderr).trim().to_string()));
    }
    serde_json::from_slice(&output.stdout).map_err(|e| unavailable(e.to_string()))
}

fn apply_helper_reply(state: &mut State, key: Key, tokens: bool, answer: Value) -> Result<(), CheckError> {
    if let Some(fatal) = answer.get("fatal") {
        return Err(CheckError::Guard(
            fatal[0].as_str().unwrap_or("Error").to_string(),
            fatal[1].as_str().unwrap_or("").to_string(),
        ));
    }
    let shown: String = answer["warnings"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect();
    if !tokens && !shown.is_empty() {
        state.warned.insert(key.clone(), shown);
    }
    if tokens {
        let found = answer["tokens"].as_array().cloned().unwrap_or_default();
        state.tokens.insert(key.2, Arc::new(found));
    } else if let Some(error) = answer.get("error") {
        state
            .parsed
            .insert(key, Parsed::Error(error.as_str().unwrap_or("").to_string()));
    } else {
        let nodes = answer["nodes"].as_array().cloned().unwrap_or_default();
        state
            .parsed
            .insert(key, Parsed::Tree(Arc::new(Tree::from_wire(&nodes))));
    }
    Ok(())
}

/// One helper run over every request not answered yet.
fn ask(requests: Vec<(Key, bool)>) -> Result<(), CheckError> {
    let mut state = STATE.lock().map_err(|_| unavailable("parser state poisoned"))?;
    let wanted = missing_requests(&state, requests);
    if wanted.is_empty() && state.stdlib.is_some() {
        return Ok(());
    }
    let reply = run_helper(&wanted)?;
    let names = |key: &str| -> HashSet<String> {
        reply[key]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .map(String::from)
            .collect()
    };
    state.stdlib = Some(Arc::new((names("stdlib"), names("builtin"))));
    let replies = reply["replies"].as_array().cloned().unwrap_or_default();
    for ((key, tokens), answer) in wanted.into_iter().zip(replies) {
        apply_helper_reply(&mut state, key, tokens, answer)?;
    }
    Ok(())
}

fn parse_key(text: &str, filename: Option<&str>) -> Key {
    ("parse", filename.map(String::from), text.to_string())
}

/// Parse many sources in one helper run.
pub fn prefetch(texts: &[&str]) -> Result<(), CheckError> {
    ask(texts.iter().map(|t| (parse_key(t, None), false)).collect())
}

/// Tokenize many sources in one helper run.
pub fn prefetch_tokens(texts: &[&str]) -> Result<(), CheckError> {
    ask(texts.iter().map(|t| (("tokens", None, t.to_string()), true)).collect())
}

/// `ast.parse(text[, filename])`, with the warnings CPython prints on every parse.
pub fn parse_named(text: &str, filename: Option<&str>) -> Result<Parsed, CheckError> {
    let key = parse_key(text, filename);
    ask(vec![(key.clone(), false)])?;
    let state = STATE.lock().map_err(|_| unavailable("parser state poisoned"))?;
    if let Some(shown) = state.warned.get(&key) {
        eprint!("{shown}");
    }
    state
        .parsed
        .get(&key)
        .cloned()
        .ok_or_else(|| unavailable("no parse result"))
}

/// A parse loki.py memoizes: warnings only the first time per (kind, path, text).
pub fn parse_memo(kind: &'static str, path: &str, text: &str) -> Result<Option<Arc<Tree>>, CheckError> {
    if first_time(kind, path, text)? {
        return parse(text);
    }
    let key = parse_key(text, None);
    ask(vec![(key.clone(), false)])?;
    let state = STATE.lock().map_err(|_| unavailable("parser state poisoned"))?;
    Ok(match state.parsed.get(&key) {
        Some(Parsed::Tree(tree)) => Some(tree.clone()),
        _ => None,
    })
}

/// `content_memo`: true the first time a (kind, path, text) analysis runs.
pub fn first_time(kind: &'static str, path: &str, text: &str) -> Result<bool, CheckError> {
    let mut state = STATE.lock().map_err(|_| unavailable("parser state poisoned"))?;
    Ok(state.memo.insert((kind, path.to_string(), text.to_string())))
}

/// The tree, or None for source CPython does not parse.
pub fn parse(text: &str) -> Result<Option<Arc<Tree>>, CheckError> {
    Ok(match parse_named(text, None)? {
        Parsed::Tree(tree) => Some(tree),
        Parsed::Error(_) => None,
    })
}

type ModuleNames = Arc<(HashSet<String>, HashSet<String>)>;

fn stdlib() -> Result<ModuleNames, CheckError> {
    ask(vec![])?;
    let state = STATE.lock().map_err(|_| unavailable("parser state poisoned"))?;
    state.stdlib.clone().ok_or_else(|| unavailable("no module list"))
}

/// Blank Python comments and string contents, keeping quotes and offsets.
pub fn mask_python(text: &Text) -> Result<Text, CheckError> {
    ask(vec![(("tokens", None, text.s.clone()), true)])?;
    let tokens = {
        let state = STATE.lock().map_err(|_| unavailable("parser state poisoned"))?;
        state.tokens.get(&text.s).cloned().unwrap_or_default()
    };
    let mut offsets = vec![0usize];
    for line in py::splitlines(&text.s, true) {
        offsets.push(offsets[offsets.len() - 1] + line.chars().count());
    }
    static QUOTE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"^[A-Za-z]*('''|"""|'|")"#).expect("static"));
    let mut chars = text.c.clone();
    for token in tokens.iter() {
        let at = |i: usize| token[i].as_u64().unwrap_or(0) as usize;
        let position = |row: usize, col: usize| offsets.get(row.saturating_sub(1)).copied().unwrap_or(0) + col;
        let start = position(at(1), at(2));
        let end = position(at(3), at(4));
        if token[0] == true {
            blank(&mut chars, start, end);
            continue;
        }
        let string = token[5].as_str().unwrap_or("");
        match QUOTE.captures(string) {
            Some(caps) => {
                let width = caps[0].chars().count();
                blank(&mut chars, start + width, end.saturating_sub(caps[1].chars().count()));
            }
            None => blank(&mut chars, start + 1, end.saturating_sub(1)),
        }
    }
    Ok(Text::from_chars(chars))
}

const REQUEST_NAMES: [&str; 6] = ["request", "req", "params", "query_params", "form", "cookies"];
const SERVER_ATTRIBUTES: [&str; 6] = ["user", "session", "auth", "state", "identity", "principal"];
const PATH_SANITIZERS: [&str; 5] = [
    "basename",
    "secure_filename",
    "is_relative_to",
    "commonpath",
    "relative_to",
];
const PATH_CALLS: [&str; 5] = ["open", "io.open", "os.path.join", "Path", "pathlib.Path"];

fn http_call(name: &str) -> bool {
    let methods = ["get", "post", "put", "patch", "delete", "head", "options"];
    ["requests.request", "httpx.request", "urllib.request.urlopen", "urlopen"].contains(&name)
        || ["requests", "httpx"].iter().any(|module| {
            name.strip_prefix(module)
                .and_then(|rest| rest.strip_prefix('.'))
                .is_some_and(|method| methods.contains(&method))
        })
}

fn is_request_owner(tree: &Tree, mut owner: usize) -> bool {
    while tree.kind(owner) == "Attribute" {
        if SERVER_ATTRIBUTES.contains(&tree.str(owner, "attr").unwrap_or("")) {
            return false;
        }
        let Some(next) = tree.node(owner, "value") else {
            return false;
        };
        owner = next;
    }
    tree.kind(owner) == "Name" && REQUEST_NAMES.contains(&tree.str(owner, "id").unwrap_or(""))
}

fn request_key_and_owner(tree: &Tree, node: usize) -> Option<(usize, usize)> {
    match tree.kind(node) {
        "Subscript" => Some((tree.node(node, "slice")?, tree.node(node, "value")?)),
        "Call" => {
            let func = tree.node(node, "func")?;
            let args = tree.list(node, "args");
            if tree.kind(func) != "Attribute" || tree.str(func, "attr") != Some("get") || args.is_empty() {
                return None;
            }
            Some((args[0], tree.node(func, "value")?))
        }
        _ => None,
    }
}

fn request_field(tree: &Tree, node: usize) -> Option<String> {
    let (key, owner) = request_key_and_owner(tree, node)?;
    let value = tree.constant_str(key)?;
    if !langrules::AUTHORIZATION_KEY.is_match(value) {
        return None;
    }
    is_request_owner(tree, owner).then(|| value.to_string())
}

fn request_source(tree: &Tree, node: usize) -> bool {
    let owner = match tree.kind(node) {
        "Subscript" => tree.node(node, "value"),
        "Call" => tree
            .node(node, "func")
            .filter(|&f| tree.kind(f) == "Attribute" && matches!(tree.str(f, "attr"), Some("get" | "getlist")))
            .and_then(|f| tree.node(f, "value")),
        "Attribute" => Some(node),
        _ => None,
    };
    owner.is_some_and(|o| is_request_owner(tree, o))
}

fn last_name(name: &str) -> &str {
    name.rsplit('.').next().unwrap_or(name)
}

fn is_tainted_item(tree: &Tree, item: usize, tainted: &HashSet<String>) -> bool {
    request_source(tree, item) || (tree.kind(item) == "Name" && tainted.contains(tree.str(item, "id").unwrap_or("")))
}

fn record_tainted_targets(tree: &Tree, node: usize, tainted: &mut HashSet<String>) {
    let targets = if tree.kind(node) == "Assign" {
        tree.list(node, "targets")
    } else {
        tree.node(node, "target").into_iter().collect()
    };
    for target in targets {
        for item in tree.walk(target) {
            if tree.kind(item) == "Name" {
                tainted.insert(tree.str(item, "id").unwrap_or("").to_string());
            }
        }
    }
}

fn collect_tainted_names(tree: &Tree, walked: &[usize]) -> HashSet<String> {
    let mut tainted: HashSet<String> = HashSet::new();
    for _ in 0..2 {
        for &node in walked {
            if !tree.is(node, &["Assign", "AnnAssign"]) {
                continue;
            }
            let Some(value) = tree.node(node, "value") else {
                continue;
            };
            if tree.walk(value).iter().any(|&item| is_tainted_item(tree, item, &tainted)) {
                record_tainted_targets(tree, node, &mut tainted);
            }
        }
    }
    tainted
}

fn find_tainted_sink(
    tree: &Tree,
    walked: &[usize],
    tainted: &HashSet<String>,
    sink: &impl Fn(&str) -> bool,
    arguments: &impl Fn(usize) -> Vec<usize>,
) -> Option<usize> {
    for &node in walked {
        if tree.kind(node) != "Call" || !sink(tree.func_text(node)) {
            continue;
        }
        if arguments(node)
            .iter()
            .any(|&a| tree.walk(a).iter().any(|&item| is_tainted_item(tree, item, tainted)))
        {
            return Some(node);
        }
    }
    None
}

fn request_tainted_calls(
    tree: &Tree,
    sink: impl Fn(&str) -> bool,
    arguments: impl Fn(usize) -> Vec<usize>,
    sanitizer: impl Fn(&str) -> bool,
) -> Vec<usize> {
    let mut scopes = vec![0usize];
    scopes.extend(
        tree.walk(0)
            .into_iter()
            .filter(|&n| tree.is(n, &["FunctionDef", "AsyncFunctionDef"])),
    );
    let mut calls: Vec<usize> = Vec::new();
    for scope in scopes {
        let walked = tree.walk(scope);
        // Taint starts only at request data, so a scope that reads none has no findings.
        if !walked.iter().any(|&n| request_source(tree, n))
            || walked
                .iter()
                .any(|&n| tree.kind(n) == "Call" && sanitizer(last_name(tree.func_text(n))))
        {
            continue;
        }
        let tainted = collect_tainted_names(tree, &walked);
        if let Some(node) = find_tainted_sink(tree, &walked, &tainted, &sink, &arguments) {
            calls.push(node);
        }
    }
    let mut seen = HashSet::new();
    calls.retain(|&c| seen.insert((tree.line(c), tree.col(c))));
    calls
}

fn secret_value(tree: &Tree, node: usize, derived: &HashSet<String>) -> bool {
    if tree.kind(node) == "Call"
        && let Some(func) = tree.node(node, "func")
        && tree.kind(func) == "Attribute"
    {
        return matches!(tree.str(func, "attr"), Some("digest" | "hexdigest"));
    }
    let name = match tree.kind(node) {
        "Attribute" => tree.str(node, "attr").unwrap_or(""),
        _ => tree.str(node, "id").unwrap_or(""),
    };
    static SECRET: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)(?:signature|hmac|digest)$").expect("static"));
    derived.contains(name) || SECRET.is_match(name)
}

fn computed_call(tree: &Tree, node: usize, values: &HashMap<String, String>) -> Option<String> {
    match tree.kind(node) {
        "Name" => values.get(tree.str(node, "id").unwrap_or("")).cloned(),
        "Call" => Some(tree.dump(node)),
        _ => None,
    }
}

fn assigned_call_dumps(tree: &Tree, walked: &[usize]) -> HashMap<String, String> {
    let mut values: HashMap<String, String> = HashMap::new();
    for &node in walked {
        if tree.kind(node) != "Assign" {
            continue;
        }
        let Some(value) = tree.node(node, "value").filter(|&v| tree.kind(v) == "Call") else {
            continue;
        };
        for target in tree.list(node, "targets") {
            if tree.kind(target) == "Name" {
                values.insert(tree.str(target, "id").unwrap_or("").to_string(), tree.dump(value));
            }
        }
    }
    values
}

fn equality_assertion_pair(tree: &Tree, node: usize) -> Option<(usize, usize)> {
    let pair: Vec<usize> = if tree.kind(node) == "Call"
        && let Some(func) = tree.node(node, "func")
        && tree.kind(func) == "Attribute"
        && matches!(
            tree.str(func, "attr"),
            Some("assertEqual" | "assertEquals" | "assertAlmostEqual")
        ) {
        tree.list(node, "args").into_iter().take(2).collect()
    } else if tree.kind(node) == "Assert"
        && let Some(test) = tree.node(node, "test")
        && tree.kind(test) == "Compare"
        && tree.list(test, "ops").first().is_some_and(|&op| tree.kind(op) == "Eq")
    {
        tree.node(test, "left")
            .into_iter()
            .chain(tree.list(test, "comparators").into_iter().take(1))
            .collect()
    } else {
        return None;
    };
    (pair.len() == 2).then(|| (pair[0], pair[1]))
}

fn tautological_assertions(tree: &Tree) -> Vec<usize> {
    let mut found = Vec::new();
    for function in tree.walk(0) {
        if !tree.is(function, &["FunctionDef", "AsyncFunctionDef"])
            || !tree.str(function, "name").unwrap_or("").starts_with("test")
        {
            continue;
        }
        let walked = tree.walk(function);
        let values = assigned_call_dumps(tree, &walked);
        for &node in &walked {
            if let Some((left, right)) = equality_assertion_pair(tree, node)
                && let Some(first) = computed_call(tree, left, &values)
                && Some(first) == computed_call(tree, right, &values)
            {
                found.push(node);
            }
        }
    }
    found
}

fn index_error() -> CheckError {
    CheckError::Guard("IndexError".into(), "list index out of range".into())
}

fn line_offsets(text: &str) -> Vec<usize> {
    let mut offsets = vec![0usize];
    for line in py::splitlines(text, true) {
        offsets.push(offsets[offsets.len() - 1] + line.chars().count());
    }
    offsets
}

fn node_offset(tree: &Tree, offsets: &[usize], node: usize) -> Result<usize, CheckError> {
    let line = tree.line(node);
    let start = usize::try_from(line - 1)
        .ok()
        .and_then(|l| offsets.get(l))
        .ok_or_else(index_error)?;
    Ok((*start as i64 + tree.col(node)).max(0) as usize)
}

fn check_request_auth(
    tree: &Tree,
    walked: &[usize],
    offsets: &[usize],
    findings: &mut Vec<crate::rules::Finding>,
) -> Result<(), CheckError> {
    for &node in walked {
        let operands: Vec<usize> = match tree.kind(node) {
            "Compare" => tree
                .node(node, "left")
                .into_iter()
                .chain(tree.list(node, "comparators"))
                .collect(),
            "BoolOp" => tree.list(node, "values"),
            "UnaryOp" if tree.node(node, "op").is_some_and(|op| tree.kind(op) == "Not") => {
                tree.node(node, "operand").into_iter().collect()
            }
            "If" | "IfExp" | "While" | "Assert" => tree.node(node, "test").into_iter().collect(),
            _ => continue,
        };
        for operand in operands {
            if let Some(key) = request_field(tree, operand) {
                findings.push((
                    "loki/request-authorization",
                    format!(
                        "authorization decision trusts client-controlled request field \"{key}\"; derive privilege from the authenticated server-side identity"
                    ),
                    node_offset(tree, offsets, operand)?,
                ));
            }
        }
    }
    Ok(())
}

fn collect_derived_secrets(tree: &Tree, walked: &[usize]) -> HashSet<String> {
    let mut derived: HashSet<String> = HashSet::new();
    for &node in walked {
        if tree.kind(node) == "Assign"
            && let Some(value) = tree.node(node, "value")
            && tree
                .walk(value)
                .iter()
                .any(|&item| secret_value(tree, item, &HashSet::new()))
        {
            for target in tree.list(node, "targets") {
                if tree.kind(target) == "Name" {
                    derived.insert(tree.str(target, "id").unwrap_or("").to_string());
                }
            }
        }
    }
    derived
}

fn is_shell_command_injection(tree: &Tree, node: usize) -> bool {
    if tree.kind(node) != "Call"
        || !["run", "call", "Popen", "check_call", "check_output"].contains(&last_name(tree.func_text(node)))
    {
        return false;
    }
    let Some(&first) = tree.list(node, "args").first() else {
        return false;
    };
    if tree.kind(first) != "List" {
        return false;
    }
    let constant: Vec<Option<&Const>> = tree
        .list(first, "elts")
        .into_iter()
        .map(|item| tree.constant(item).filter(|c| c.kind != "NoneType"))
        .collect();
    fn text_of<'a>(c: &Option<&'a Const>) -> Option<&'a str> {
        c.and_then(|c| if c.kind == "str" { c.text.as_deref() } else { None })
    }
    let dash_c = constant.iter().position(|c| text_of(c) == Some("-c"));
    let Some((head, dash)) = constant.first().zip(dash_c) else {
        return false;
    };
    text_of(head).is_some_and(|program| langrules::SHELLS.contains(&program))
        && constant[dash..].iter().any(Option::is_none)
}

fn is_timing_compare(tree: &Tree, node: usize, derived: &HashSet<String>) -> bool {
    if tree.kind(node) != "Compare" || !tree.list(node, "ops").iter().all(|&op| tree.is(op, &["Eq", "NotEq"])) {
        return false;
    }
    let operands: Vec<usize> = tree
        .node(node, "left")
        .into_iter()
        .chain(tree.list(node, "comparators"))
        .collect();
    operands.iter().any(|&item| secret_value(tree, item, derived))
        && !operands.iter().any(|&item| tree.kind(item) == "Constant")
}

fn check_shell_and_timing(
    tree: &Tree,
    walked: &[usize],
    offsets: &[usize],
    findings: &mut Vec<crate::rules::Finding>,
) -> Result<(), CheckError> {
    let derived = collect_derived_secrets(tree, walked);
    for &node in walked {
        if is_shell_command_injection(tree, node) {
            findings.push((
                "loki/command-injection",
                langrules::SHELL_COMMAND.into(),
                node_offset(tree, offsets, node)?,
            ));
        }
        if is_timing_compare(tree, node, &derived) {
            findings.push((
                "loki/timing-compare",
                "timing attack: signature or digest compared with ==; use hmac.compare_digest".into(),
                node_offset(tree, offsets, node)?,
            ));
        }
    }
    Ok(())
}

const REGEX_CALLS: [&str; 8] = [
    "re.compile",
    "re.match",
    "re.search",
    "re.fullmatch",
    "re.findall",
    "re.finditer",
    "re.sub",
    "re.split",
];

fn check_regex_redos(
    tree: &Tree,
    walked: &[usize],
    offsets: &[usize],
    findings: &mut Vec<crate::rules::Finding>,
) -> Result<(), CheckError> {
    for &node in walked {
        if tree.kind(node) == "Call"
            && REGEX_CALLS.contains(&tree.func_text(node))
            && let Some(&first) = tree.list(node, "args").first()
            && let Some(pattern) = tree.constant_str(first)
            && jsrules::nested_quantifier(pattern)
        {
            findings.push((
                jsrules::REDOS_RULE,
                jsrules::REDOS_MESSAGE.into(),
                node_offset(tree, offsets, node)?,
            ));
        }
    }
    Ok(())
}

fn keyword_values(tree: &Tree, call: usize) -> Vec<(Option<String>, usize)> {
    tree.list(call, "keywords")
        .into_iter()
        .filter_map(|k| tree.node(k, "value").map(|v| (tree.str(k, "arg").map(String::from), v)))
        .collect()
}

fn url_arguments(tree: &Tree, call: usize) -> Vec<usize> {
    tree.list(call, "args")
        .into_iter()
        .take(1)
        .chain(
            keyword_values(tree, call)
                .into_iter()
                .filter(|(k, _)| k.as_deref() == Some("url"))
                .map(|(_, v)| v),
        )
        .collect()
}

fn check_traversal_tautology_ssrf(
    tree: &Tree,
    offsets: &[usize],
    findings: &mut Vec<crate::rules::Finding>,
) -> Result<(), CheckError> {
    let traversal = request_tainted_calls(
        tree,
        |name| PATH_CALLS.contains(&name) || name.ends_with(".joinpath"),
        |call| {
            tree.list(call, "args")
                .into_iter()
                .chain(keyword_values(tree, call).into_iter().map(|(_, v)| v))
                .collect()
        },
        |name| PATH_SANITIZERS.contains(&name),
    );
    for call in traversal {
        findings.push((
            "loki/path-traversal",
            "path traversal: file path built from request data; take the base name or resolve it and check it stays under the intended directory".into(),
            node_offset(tree, offsets, call)?,
        ));
    }
    for call in tautological_assertions(tree) {
        findings.push((
            "loki/tautological-test",
            "tautological assertion: the expected value is computed by the same call as the result, so the test always passes".into(),
            node_offset(tree, offsets, call)?,
        ));
    }
    for call in request_tainted_calls(tree, http_call, |call| url_arguments(tree, call), |_| false) {
        findings.push((
            "loki/ssrf",
            "server-side request forgery (SSRF): outbound request URL comes from request data; validate the host against an allowlist".into(),
            node_offset(tree, offsets, call)?,
        ));
    }
    Ok(())
}

fn is_unverified_hostname_assign(tree: &Tree, node: usize) -> bool {
    tree.node(node, "value")
        .and_then(|v| tree.constant(v))
        .is_some_and(|c| c.repr == "False")
        && tree
            .list(node, "targets")
            .iter()
            .any(|&t| tree.kind(t) == "Attribute" && tree.str(t, "attr") == Some("check_hostname"))
}

fn check_call_sql_yaml_tls(
    tree: &Tree,
    node: usize,
    offsets: &[usize],
    findings: &mut Vec<crate::rules::Finding>,
) -> Result<(), CheckError> {
    let name = tree.func_text(node);
    if SQL_CALLS.contains(&last_name(name))
        && let Some(&first) = tree.list(node, "args").first()
        && built_sql(tree, first)
    {
        findings.push((
            "loki/sql-injection",
            jsrules::SQL_QUERY.into(),
            node_offset(tree, offsets, node)?,
        ));
    }
    if unsafe_yaml(tree, node) {
        findings.push((
            "loki/unsafe-deserialization",
            format!(
                "unsafe deserialization: {name} without SafeLoader can build arbitrary Python objects; use yaml.safe_load"
            ),
            node_offset(tree, offsets, node)?,
        ));
    }
    if tls_unverified(tree, node) {
        findings.push((
            "loki/tls-verification",
            jsrules::TLS_VERIFICATION.into(),
            node_offset(tree, offsets, node)?,
        ));
    }
    Ok(())
}

fn check_sql_yaml_tls(
    tree: &Tree,
    walked: &[usize],
    offsets: &[usize],
    findings: &mut Vec<crate::rules::Finding>,
) -> Result<(), CheckError> {
    for &node in walked {
        if tree.kind(node) == "Assign" {
            if is_unverified_hostname_assign(tree, node) {
                findings.push((
                    "loki/tls-verification",
                    jsrules::TLS_VERIFICATION.into(),
                    node_offset(tree, offsets, node)?,
                ));
            }
        } else if tree.kind(node) == "Call" {
            check_call_sql_yaml_tls(tree, node, offsets, findings)?;
        }
    }
    Ok(())
}

fn check_eval_deserialize_redirect(
    tree: &Tree,
    offsets: &[usize],
    findings: &mut Vec<crate::rules::Finding>,
) -> Result<(), CheckError> {
    let first = |call: usize| tree.list(call, "args").into_iter().take(1).collect::<Vec<_>>();
    for call in request_tainted_calls(
        tree,
        |name| ["eval", "exec", "compile"].contains(&name),
        first,
        |_| false,
    ) {
        findings.push((
            "loki/code-eval",
            format!(
                "dynamic code execution: non-literal source passed to {}",
                tree.func_text(call)
            ),
            node_offset(tree, offsets, call)?,
        ));
    }
    for call in request_tainted_calls(tree, deserialize_call, first, |_| false) {
        findings.push((
            "loki/unsafe-deserialization",
            format!(
                "unsafe deserialization: request data passed to {} can run arbitrary code; use JSON or verify a signature first",
                tree.func_text(call)
            ),
            node_offset(tree, offsets, call)?,
        ));
    }
    let redirects = request_tainted_calls(
        tree,
        |name| {
            REDIRECT_CALLS.contains(&name) || (REDIRECT_CALLS.contains(&last_name(name)) && !name.starts_with("self."))
        },
        |call| url_arguments(tree, call),
        |name| REDIRECT_SANITIZER.is_match(name),
    );
    for call in redirects {
        findings.push((
            "loki/open-redirect",
            jsrules::OPEN_REDIRECT.into(),
            node_offset(tree, offsets, call)?,
        ));
    }
    Ok(())
}

/// `python_rules`: findings at loki.py's offsets (line start in characters plus
/// the node's UTF-8 column).
pub fn python_rules(text: &Text) -> Result<Vec<crate::rules::Finding>, CheckError> {
    let Some(tree) = parse(&text.s)? else { return Ok(vec![]) };
    let tree = tree.as_ref();
    let offsets = line_offsets(&text.s);
    let walked = tree.walk(0);
    let mut findings: Vec<crate::rules::Finding> = Vec::new();
    check_request_auth(tree, &walked, &offsets, &mut findings)?;
    check_shell_and_timing(tree, &walked, &offsets, &mut findings)?;
    check_regex_redos(tree, &walked, &offsets, &mut findings)?;
    check_traversal_tautology_ssrf(tree, &offsets, &mut findings)?;
    check_sql_yaml_tls(tree, &walked, &offsets, &mut findings)?;
    check_eval_deserialize_redirect(tree, &offsets, &mut findings)?;
    Ok(findings)
}

const SQL_CALLS: [&str; 5] = ["execute", "executemany", "executescript", "raw", "text"];
const REDIRECT_CALLS: [&str; 3] = ["redirect", "RedirectResponse", "HttpResponseRedirect"];
const UNSAFE_YAML_LOADERS: [&str; 6] = [
    "Loader",
    "FullLoader",
    "UnsafeLoader",
    "CLoader",
    "CFullLoader",
    "CUnsafeLoader",
];
const HTTP_CLIENT_METHODS: [&str; 12] = [
    "get",
    "post",
    "put",
    "patch",
    "delete",
    "head",
    "options",
    "request",
    "send",
    "stream",
    "Client",
    "AsyncClient",
];
// Text just before a hole that puts it where SQL expects a value, not a clause or name.
static SQL_VALUE_POSITION: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)(?:[=<>(,]|\b(?:like|in|values|limit|offset))\s*$").unwrap());
static SQL_VERB: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)\b(?:select|insert|update|delete)\b").unwrap());
static PERCENT_HOLE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"%(?:\(\w+\))?[sdifr]").unwrap());
static FORMAT_HOLE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\{[^{}]*\}").unwrap());
static REDIRECT_SANITIZER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)safe|saniti|valid|allowed|trusted").unwrap());

fn deserialize_call(name: &str) -> bool {
    name.split_once('.').is_some_and(|(module, call)| {
        ["pickle", "cPickle", "_pickle", "dill", "marshal"].contains(&module) && ["load", "loads"].contains(&call)
    })
}

/// `str(value)` of a `Constant`: the text of a `str`, else its `ascii()`.
fn constant_text(tree: &Tree, node: usize) -> Option<String> {
    tree.constant(node)
        .map(|c| c.text.clone().unwrap_or_else(|| c.repr.clone()))
}

fn is_add(tree: &Tree, node: usize) -> bool {
    tree.kind(node) == "BinOp" && tree.node(node, "op").is_some_and(|op| tree.kind(op) == "Add")
}

/// The operands of a chain of `+` additions.
fn addends(tree: &Tree, node: usize) -> Vec<usize> {
    if is_add(tree, node) {
        let mut out = tree.node(node, "left").map(|l| addends(tree, l)).unwrap_or_default();
        out.extend(tree.node(node, "right").map(|r| addends(tree, r)).unwrap_or_default());
        return out;
    }
    vec![node]
}

fn sql_holes(text: &str, re: &Regex) -> Vec<String> {
    re.find_iter(text).map(|m| text[..m.start()].to_string()).collect()
}

fn joined_str_parts(tree: &Tree, node: usize) -> (String, Vec<String>) {
    let mut text = String::new();
    let mut befores = Vec::new();
    for value in tree.list(node, "values") {
        if tree.kind(value) == "FormattedValue" {
            befores.push(text.clone());
        } else if let Some(part) = constant_text(tree, value) {
            text += &part;
        }
    }
    (text, befores)
}

fn add_expr_parts(tree: &Tree, node: usize) -> (String, Vec<String>) {
    let mut text = String::new();
    let mut befores = Vec::new();
    for item in addends(tree, node) {
        match constant_text(tree, item) {
            Some(part) => text += &part,
            None => befores.push(text.clone()),
        }
    }
    (text, befores)
}

fn mod_expr_parts(tree: &Tree, node: usize) -> Option<(String, Vec<String>)> {
    let left = tree.node(node, "left").and_then(|l| constant_text(tree, l))?;
    tree.node(node, "right")
        .is_some_and(|r| tree.kind(r) != "Constant")
        .then(|| {
            let befores = sql_holes(&left, &PERCENT_HOLE);
            (left, befores)
        })
}

fn format_call_parts(tree: &Tree, node: usize) -> Option<(String, Vec<String>)> {
    let func = tree.node(node, "func")?;
    if tree.kind(func) != "Attribute" || tree.str(func, "attr") != Some("format") {
        return None;
    }
    if tree.list(node, "args").is_empty() && tree.list(node, "keywords").is_empty() {
        return None;
    }
    let format = tree.node(func, "value").and_then(|v| constant_text(tree, v))?;
    let befores = sql_holes(&format, &FORMAT_HOLE);
    Some((format, befores))
}

/// SQL text with a non-constant spliced in where the query expects a value.
/// Holes in clause or name positions (`WHERE 1=1 {filters}`, `FROM {table}`) pass.
fn built_sql(tree: &Tree, node: usize) -> bool {
    let (text, befores) = if tree.kind(node) == "JoinedStr" {
        joined_str_parts(tree, node)
    } else if is_add(tree, node) {
        add_expr_parts(tree, node)
    } else if tree.kind(node) == "BinOp" && tree.node(node, "op").is_some_and(|op| tree.kind(op) == "Mod") {
        mod_expr_parts(tree, node).unwrap_or_default()
    } else if tree.kind(node) == "Call" {
        format_call_parts(tree, node).unwrap_or_default()
    } else {
        (String::new(), Vec::new())
    };
    SQL_VERB.is_match(&text)
        && befores
            .iter()
            .any(|before| SQL_VALUE_POSITION.is_match(before) || before.matches('\'').count() % 2 == 1)
}

/// yaml.load without a loader or with a full one, or yaml.unsafe_load.
fn unsafe_yaml(tree: &Tree, call: usize) -> bool {
    let name = tree.func_text(call);
    if ["yaml.unsafe_load", "yaml.unsafe_load_all"].contains(&name) {
        return true;
    }
    if !["yaml.load", "yaml.load_all"].contains(&name) {
        return false;
    }
    let loader = tree.list(call, "args").get(1).copied().or_else(|| {
        tree.list(call, "keywords")
            .into_iter()
            .find(|&k| tree.str(k, "arg") == Some("Loader"))
            .and_then(|k| tree.node(k, "value"))
    });
    // ponytail: reads the last name of a Name or Attribute loader; Python's unparse-and-split also
    // matches odd expressions ending in one (`a if c else yaml.Loader`).
    loader.is_none_or(|l| match tree.kind(l) {
        "Name" => UNSAFE_YAML_LOADERS.contains(&tree.str(l, "id").unwrap_or("")),
        "Attribute" => UNSAFE_YAML_LOADERS.contains(&tree.str(l, "attr").unwrap_or("")),
        _ => false,
    })
}

/// An HTTP client call with verify=False, or an unverified SSL context.
fn tls_unverified(tree: &Tree, call: usize) -> bool {
    let name = tree.func_text(call);
    let module = name.split('.').next().unwrap_or(name);
    let client = ["requests", "httpx"].contains(&module) || HTTP_CLIENT_METHODS.contains(&last_name(name));
    name == "ssl._create_unverified_context"
        || (client
            && tree.list(call, "keywords").into_iter().any(|k| {
                tree.str(k, "arg") == Some("verify")
                    && tree
                        .node(k, "value")
                        .and_then(|v| tree.constant(v))
                        .is_some_and(|c| c.repr == "False")
            }))
}

const ABSTRACT_DECORATORS: [&str; 5] = [
    "abstractmethod",
    "abstractproperty",
    "abstractclassmethod",
    "abstractstaticmethod",
    "overload",
];

fn reference_name(tree: &Tree, node: usize) -> Option<String> {
    let node = match tree.kind(node) {
        "Call" => tree.node(node, "func")?,
        "Subscript" => tree.node(node, "value")?,
        _ => node,
    };
    match tree.kind(node) {
        "Attribute" => tree.str(node, "attr").map(String::from),
        "Name" => tree.str(node, "id").map(String::from),
        _ => None,
    }
}

fn interface_class(tree: &Tree, node: usize) -> bool {
    tree.list(node, "bases")
        .iter()
        .any(|&b| matches!(reference_name(tree, b).as_deref(), Some("ABC" | "Protocol")))
        || tree.list(node, "keywords").iter().any(|&k| {
            tree.str(k, "arg") == Some("metaclass")
                && tree.node(k, "value").and_then(|v| reference_name(tree, v)).as_deref() == Some("ABCMeta")
        })
}

fn is_expr_constant_kind(tree: &Tree, node: usize, kind: &str) -> bool {
    tree.kind(node) == "Expr"
        && tree
            .node(node, "value")
            .and_then(|v| tree.constant(v))
            .is_some_and(|c| c.kind == kind)
}

fn is_not_implemented_raise(tree: &Tree, statement: usize) -> bool {
    if tree.kind(statement) != "Raise" {
        return false;
    }
    let Some(exception) = tree.node(statement, "exc") else {
        return false;
    };
    let name = match tree.kind(exception) {
        "Name" => Some(exception),
        "Call" => tree.node(exception, "func"),
        _ => None,
    };
    name.is_some_and(|n| tree.kind(n) == "Name" && tree.str(n, "id") == Some("NotImplementedError"))
}

fn stub_statement(tree: &Tree, node: usize) -> Option<usize> {
    let mut body = tree.list(node, "body");
    if body.first().is_some_and(|&first| is_expr_constant_kind(tree, first, "str")) {
        body.remove(0);
    }
    if body.len() != 1 {
        return None;
    }
    let statement = body[0];
    let is_stub = tree.kind(statement) == "Pass"
        || is_expr_constant_kind(tree, statement, "ellipsis")
        || is_not_implemented_raise(tree, statement);
    is_stub.then_some(statement)
}

/// `(line, name)` of placeholder function bodies.
pub fn python_stubs(tree: &Tree) -> Vec<(i64, String)> {
    fn visit(tree: &Tree, node: usize, owner: Option<usize>, found: &mut Vec<(i64, String)>) {
        for child in tree.children(node) {
            if tree.is(child, &["FunctionDef", "AsyncFunctionDef"]) {
                let statement = stub_statement(tree, child);
                let declared = tree
                    .list(child, "decorator_list")
                    .iter()
                    .any(|&d| reference_name(tree, d).is_some_and(|n| ABSTRACT_DECORATORS.contains(&n.as_str())))
                    || owner.is_some_and(|o| interface_class(tree, o))
                    || (owner.is_some() && statement.is_some_and(|s| tree.kind(s) == "Raise"));
                if statement.is_some() && !declared {
                    found.push((tree.line(child), tree.str(child, "name").unwrap_or("").to_string()));
                }
                visit(tree, child, None, found);
            } else {
                let next = (tree.kind(child) == "ClassDef").then_some(child);
                visit(tree, child, next, found);
            }
        }
    }
    let mut found = Vec::new();
    visit(tree, 0, None, &mut found);
    found.sort();
    found
}

/// `local_python_module`: at the root, under src/, or beside the file.
pub fn local_python_module(root: &Path, module: &str, directory: Option<&Path>) -> bool {
    let mut bases = vec![root.to_path_buf(), root.join("src")];
    bases.extend(directory.map(Path::to_path_buf));
    bases
        .iter()
        .any(|base| base.join(format!("{module}.py")).is_file() || base.join(module).is_dir())
}

fn is_import_guarded_try(tree: &Tree, node: usize) -> bool {
    tree.list(node, "handlers")
        .iter()
        .any(|&handler| match tree.node(handler, "type") {
            None => true,
            Some(kind) => {
                let items = if tree.kind(kind) == "Tuple" {
                    tree.list(kind, "elts")
                } else {
                    vec![kind]
                };
                items.iter().any(|&item| {
                    matches!(
                        reference_name(tree, item).as_deref(),
                        Some("ImportError" | "ModuleNotFoundError" | "Exception")
                    )
                })
            }
        })
}

fn optional_import_nodes(tree: &Tree, walked: &[usize]) -> HashSet<usize> {
    let mut optional: HashSet<usize> = HashSet::new();
    for &node in walked {
        if tree.kind(node) == "Try" && is_import_guarded_try(tree, node) {
            for statement in tree.list(node, "body") {
                optional.extend(tree.walk(statement));
            }
        }
    }
    optional
}

fn extract_node_imports(tree: &Tree, node: usize, imported: &mut Vec<(i64, String)>) {
    if tree.kind(node) == "Import" {
        for alias in tree.list(node, "names") {
            let name = tree.str(alias, "name").unwrap_or("");
            imported.push((tree.line(node), name.split('.').next().unwrap_or("").to_string()));
        }
    } else if tree.kind(node) == "ImportFrom"
        && matches!(tree.get(node, "level"), F::Int(0))
        && let Some(module) = tree.str(node, "module").filter(|m| !m.is_empty())
    {
        imported.push((tree.line(node), module.split('.').next().unwrap_or("").to_string()));
    }
}

/// `(line, module)` of absolute imports nothing in the repository explains.
pub fn python_unknown_imports(
    tree: &Tree,
    root: &Path,
    directory: &Path,
    declared: &BTreeSet<String>,
) -> Result<Vec<(i64, String)>, CheckError> {
    let names = stdlib()?;
    let walked = tree.walk(0);
    let optional = optional_import_nodes(tree, &walked);
    let mut imported: Vec<(i64, String)> = Vec::new();
    for &node in &walked {
        if !optional.contains(&node) {
            extract_node_imports(tree, node, &mut imported);
        }
    }
    Ok(imported
        .into_iter()
        .filter(|(_, module)| {
            !names.0.contains(module)
                && !names.1.contains(module)
                && module != "__main__"
                && !declared.contains(&module.to_lowercase().replace('-', "_"))
                && !local_python_module(root, module, Some(directory))
        })
        .collect())
}

/// A function's measured shape (loki.py's `FunctionMetric`).
#[derive(Debug, Clone, PartialEq)]
pub struct FunctionMetric {
    pub path: String,
    pub name: String,
    pub start: i64,
    pub end: i64,
    pub complexity: i64,
    pub sloc: i64,
    pub nesting: i64,
}

impl FunctionMetric {
    pub fn mass(&self) -> f64 {
        self.complexity as f64 * (self.sloc as f64).sqrt()
    }
}

/// Exact McCabe-style complexity; nested functions count for themselves.
pub fn python_functions(path: &str, text: &str) -> Result<Vec<FunctionMetric>, CheckError> {
    let Some(tree) = parse_memo("python-functions", path, text)? else {
        return Ok(vec![]);
    };
    let tree = tree.as_ref();
    let lines = py::splitlines(text, false);
    fn decisions(tree: &Tree, node: usize, depth: i64) -> (i64, i64) {
        let (mut total, mut deepest) = (0i64, depth);
        for child in tree.children(node) {
            if tree.is(child, &["FunctionDef", "AsyncFunctionDef", "Lambda"]) {
                continue;
            }
            let nested = tree.is(child, &["If", "For", "AsyncFor", "While", "Try", "With", "Match"]);
            if tree.is(child, &["If", "For", "AsyncFor", "While", "IfExp", "ExceptHandler"]) {
                total += 1;
            } else if tree.kind(child) == "match_case" {
                let pattern = tree.node(child, "pattern");
                let wildcard = pattern.is_some_and(|p| tree.kind(p) == "MatchAs" && tree.node(p, "pattern").is_none());
                if !wildcard {
                    total += 1;
                }
            } else if tree.kind(child) == "BoolOp" {
                total += tree.list(child, "values").len() as i64 - 1;
            } else if tree.kind(child) == "comprehension" {
                total += 1 + tree.list(child, "ifs").len() as i64;
            }
            let (count, reached) = decisions(tree, child, if nested { depth + 1 } else { depth });
            total += count;
            deepest = deepest.max(reached);
        }
        (total, deepest)
    }
    let mut results = Vec::new();
    for node in tree.walk(0) {
        if !tree.is(node, &["FunctionDef", "AsyncFunctionDef"]) {
            continue;
        }
        let start = tree.line(node);
        let end = tree.end_line(node).filter(|&e| e != 0).unwrap_or(start);
        let (count, depth) = decisions(tree, node, 0);
        let sloc = lines
            .iter()
            .skip((start - 1).max(0) as usize)
            .take((end - start + 1).max(0) as usize)
            .filter(|line| {
                let stripped = py::strip(line);
                !stripped.is_empty() && !stripped.starts_with('#')
            })
            .count() as i64;
        results.push(FunctionMetric {
            path: path.to_string(),
            name: tree.str(node, "name").unwrap_or("").to_string(),
            start,
            end,
            complexity: 1 + count,
            sloc,
            nesting: depth,
        });
    }
    Ok(results)
}

/// `(relative level or None for import, module, names)` for each import.
pub type PyImport = (Option<i64>, String, Vec<String>);

pub fn python_imports(path: &str, text: &str) -> Result<Vec<PyImport>, CheckError> {
    let Some(tree) = parse_memo("imports", path, text)? else {
        return Ok(vec![]);
    };
    let tree = tree.as_ref();
    let mut found = Vec::new();
    for node in tree.walk(0) {
        let names = || -> Vec<String> {
            tree.list(node, "names")
                .iter()
                .map(|&a| tree.str(a, "name").unwrap_or("").to_string())
                .collect()
        };
        match tree.kind(node) {
            "Import" => found.push((None, String::new(), names())),
            "ImportFrom" => {
                let level = match tree.get(node, "level") {
                    F::Int(l) => *l,
                    _ => 0,
                };
                found.push((Some(level), tree.str(node, "module").unwrap_or("").to_string(), names()));
            }
            _ => {}
        }
    }
    Ok(found)
}

fn node_line_span(tree: &Tree, node: usize) -> std::ops::RangeInclusive<i64> {
    let start = tree.line(node);
    start..=tree.end_line(node).filter(|&e| e != 0).unwrap_or(start)
}

fn is_bool_return(tree: &Tree, node: usize) -> bool {
    tree.kind(node) == "Return"
        && tree
            .node(node, "value")
            .and_then(|v| tree.constant(v))
            .is_some_and(|c| c.kind == "bool")
}

fn is_redundant_bool_if(tree: &Tree, node: usize) -> bool {
    if tree.kind(node) != "If" {
        return false;
    }
    let (body, orelse) = (tree.list(node, "body"), tree.list(node, "orelse"));
    body.len() == 1 && orelse.len() == 1 && is_bool_return(tree, body[0]) && is_bool_return(tree, orelse[0])
}

fn is_redundant_reraise_try(tree: &Tree, node: usize) -> bool {
    if tree.kind(node) != "Try" {
        return false;
    }
    let handlers = tree.list(node, "handlers");
    if handlers.is_empty() || !tree.list(node, "finalbody").is_empty() || !tree.list(node, "orelse").is_empty() {
        return false;
    }
    handlers.iter().all(|&h| {
        let body = tree.list(h, "body");
        body.len() == 1 && tree.kind(body[0]) == "Raise" && tree.node(body[0], "exc").is_none()
    })
}

fn flag_assign_then_return(tree: &Tree, node: usize, flagged: &mut BTreeSet<i64>) {
    if !matches!(tree.get(node, "body"), F::List(_)) {
        return;
    }
    let body = tree.list(node, "body");
    for pair in body.windows(2) {
        let (first, second) = (pair[0], pair[1]);
        let targets = tree.list(first, "targets");
        if tree.kind(first) == "Assign"
            && targets.len() == 1
            && tree.kind(targets[0]) == "Name"
            && tree.kind(second) == "Return"
            && let Some(value) = tree.node(second, "value")
            && tree.kind(value) == "Name"
            && tree.str(value, "id") == tree.str(targets[0], "id")
        {
            flagged.insert(tree.line(first));
            flagged.insert(tree.line(second));
        }
    }
}

fn flag_commented_code(text: &str, flagged: &mut BTreeSet<i64>) -> Result<(), CheckError> {
    let comments: Vec<(i64, String)> = py::splitlines(text, false)
        .iter()
        .enumerate()
        .filter_map(|(i, line)| {
            let stripped = py::strip(line);
            (stripped.starts_with('#') && stripped.chars().count() > 2)
                .then(|| (i as i64 + 1, py::strip(&stripped[1..]).to_string()))
        })
        .collect();
    prefetch(&comments.iter().map(|(_, c)| c.as_str()).collect::<Vec<_>>())?;
    for (number, code) in comments {
        if let Some(parsed) = parse(&code)? {
            let body = parsed.list(0, "body");
            if let Some(&first) = body.first()
                && !parsed.is(first, &["Expr", "Pass"])
            {
                flagged.insert(number);
            }
        }
    }
    Ok(())
}

/// Lines of Python code matching loki.py's verbosity heuristics.
pub fn python_verbose_lines(text: &str) -> Result<BTreeSet<i64>, CheckError> {
    let mut flagged = BTreeSet::new();
    let Some(tree) = parse(text)? else { return Ok(flagged) };
    let tree = tree.as_ref();
    for node in tree.walk(0) {
        if is_redundant_bool_if(tree, node) || is_redundant_reraise_try(tree, node) {
            flagged.extend(node_line_span(tree, node));
        }
        if tree.kind(node) == "Compare"
            && tree
                .list(node, "comparators")
                .iter()
                .any(|&c| tree.constant(c).is_some_and(|c| c.kind == "bool"))
        {
            flagged.insert(tree.line(node));
        }
        flag_assign_then_return(tree, node, &mut flagged);
    }
    flag_commented_code(text, &mut flagged)?;
    Ok(flagged)
}

/// Whether mypy's default mode would check more than module-level code.
pub fn annotated_python(text: &str) -> Result<bool, CheckError> {
    let Some(tree) = parse(text)? else { return Ok(false) };
    for node in tree.walk(0) {
        if tree.kind(node) == "AnnAssign" {
            return Ok(true);
        }
        if tree.is(node, &["FunctionDef", "AsyncFunctionDef"]) {
            if tree.node(node, "returns").is_some() {
                return Ok(true);
            }
            if let Some(args) = tree.node(node, "args") {
                let annotated = ["posonlyargs", "args", "kwonlyargs"]
                    .iter()
                    .flat_map(|name| tree.list(args, name))
                    .any(|argument| tree.node(argument, "annotation").is_some());
                if annotated {
                    return Ok(true);
                }
            }
        }
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules(source: &str) -> Vec<&'static str> {
        python_rules(&Text::new(source))
            .unwrap()
            .into_iter()
            .map(|(rule, _, _)| rule)
            .collect()
    }

    #[test]
    fn python_injection_rules_match_python() {
        let deserialize = "loki/unsafe-deserialization";
        for (source, expected) in [
            (
                "cur.execute(f\"SELECT * FROM t WHERE id = {i}\")\n",
                vec!["loki/sql-injection"],
            ),
            (
                "cur.execute('SELECT * FROM t WHERE id = %s' % i)\n",
                vec!["loki/sql-injection"],
            ),
            (
                "s.execute(text('DELETE FROM t WHERE a = ' + a))\n",
                vec!["loki/sql-injection"],
            ),
            ("cur.execute('SELECT * FROM t WHERE id = %s', (i,))\n", vec![]),
            ("cur.execute(f\"SELECT * FROM {table} WHERE 1=1 {filters}\")\n", vec![]),
            ("def f(request):\n    eval(request.form['c'])\n", vec!["loki/code-eval"]),
            ("def f(request):\n    eval(expression)\n", vec![]),
            ("def f(request):\n    pickle.loads(request.body)\n", vec![deserialize]),
            ("pickle.loads(cache_blob)\n", vec![]),
            ("yaml.load(f)\nyaml.unsafe_load(f)\n", vec![deserialize, deserialize]),
            ("yaml.load(f, Loader=yaml.SafeLoader)\nyaml.safe_load(f)\n", vec![]),
            ("requests.get(u, verify=False)\n", vec!["loki/tls-verification"]),
            (
                "ctx = ssl._create_unverified_context()\n",
                vec!["loki/tls-verification"],
            ),
            ("ctx.check_hostname = False\n", vec!["loki/tls-verification"]),
            ("requests.get(u, verify=True)\ndispatch(f, verify=False)\n", vec![]),
            (
                "def f(request):\n    return redirect(request.args['next'])\n",
                vec!["loki/open-redirect"],
            ),
            (
                "def f(request):\n    url = request.GET.get('next')\n    return HttpResponseRedirect(url_has_allowed_host_and_scheme(url) and url)\n",
                vec![],
            ),
        ] {
            assert_eq!(rules(source), expected, "{source}");
        }
    }
}
