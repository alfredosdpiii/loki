//! Structural sloppiness: complexity erosion, duplication and import cycles
//! (`loki slop`, and the advisory notes `hook` adds for written files).

use crate::git::{self, git_output, head_text};
use crate::hook::is_test_path;
use crate::jsrules::re;
use crate::proc::{self, Deadline};
use crate::py;
use crate::pyast::{self, FunctionMetric};
use crate::text::{Re, Text, mask_elixir, mask_javascript, mask_rust, matching_close};
use crate::{CheckError, MAX_VIOLATIONS, config::PROTECTED_PATHS, path_matches, resolve};
use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{LazyLock, Mutex};

pub const SLOP_COMPLEXITY: i64 = 10;
const CLONE_MIN_TOKENS: usize = 100;
const CLONE_MIN_LINES: i64 = 3;
const SLOP_WRITE_BUDGET: u64 = 2 * 1024 * 1024;
const BRACE_LANGUAGES: [&str; 8] = ["java", "kotlin", "csharp", "c", "cpp", "swift", "scala", "php"];
const EXACT_COMPLEXITY: [&str; 4] = ["python", "typescript", "go", "elixir"];
const EXCLUDED_DIRECTORIES: [&str; 9] = [
    "vendor",
    "third_party",
    "third-party",
    "external",
    "generated",
    "dist",
    "build",
    "target",
    "coverage",
];
pub const SKIP_DIRECTORIES: [&str; 10] = [
    ".git",
    ".loki",
    ".mutmut-cache",
    ".venv",
    "mutants",
    "node_modules",
    "venv",
    "__pycache__",
    "deps",
    "_build",
];

fn keywords(family: &str) -> &'static str {
    match family {
        "python" => {
            "and as assert async await break class continue def del elif else except finally for from global if import in is lambda nonlocal not or pass raise return try while with yield None True False match case"
        }
        "typescript" => {
            "async await break case catch class const continue default delete do else enum export extends false finally for function if import in instanceof let new null of return static super switch this throw true try typeof var void while yield interface type implements"
        }
        "go" => {
            "break case chan const continue default defer else fallthrough for func go goto if import interface map package range return select struct switch type var nil true false"
        }
        "rust" => {
            "as async await break const continue crate else enum extern false fn for if impl in let loop match mod move mut pub ref return self Self static struct super trait true type unsafe use where while"
        }
        "elixir" => {
            "after and case catch cond def defp defmodule defstruct do else end fn for if in nil not or raise receive rescue true false try unless when with"
        }
        "ruby" => {
            "begin break case class def do else elsif end ensure false for if in module next nil not or and rescue return self then true unless until when while yield"
        }
        _ => {
            "abstract break case catch class const continue default do else enum extends false final finally for foreach func fun function if implements import in interface internal let namespace new null override private protected public return static struct super switch this throw true try val var void when while"
        }
    }
}

const EXTRA_LANGUAGES: [(&str, &str); 15] = [
    (".java", "java"),
    (".kt", "kotlin"),
    (".kts", "kotlin"),
    (".cs", "csharp"),
    (".c", "c"),
    (".h", "c"),
    (".cc", "cpp"),
    (".cpp", "cpp"),
    (".cxx", "cpp"),
    (".hpp", "cpp"),
    (".hh", "cpp"),
    (".swift", "swift"),
    (".scala", "scala"),
    (".php", "php"),
    (".rb", "ruby"),
];

/// `slop_language`: Loki languages plus the structurally measured extras.
pub fn slop_language(path: &str) -> Option<&'static str> {
    if let Some(language) = crate::rules::language(path) {
        return Some(language);
    }
    let suffix = crate::rules::suffix(path)?;
    EXTRA_LANGUAGES
        .iter()
        .find(|&&(ext, _)| ext == suffix)
        .map(|&(_, lang)| lang)
}

fn slop_mask(language: &str, text: &Text) -> Result<Text, CheckError> {
    Ok(match language {
        "python" => pyast::mask_python(text)?,
        "typescript" => mask_javascript(text),
        "elixir" | "ruby" => mask_elixir(text),
        _ => mask_rust(text),
    })
}

/// Python list slicing bounds for `items[a:b]`.
fn py_range(len: usize, a: i64, b: i64) -> std::ops::Range<usize> {
    let clamp = |i: i64| -> usize {
        let i = if i < 0 { i + len as i64 } else { i };
        i.clamp(0, len as i64) as usize
    };
    let (start, stop) = (clamp(a), clamp(b));
    start..stop.max(start)
}

fn source_lines(masked: &str, start: i64, end: i64) -> i64 {
    let lines = py::splitlines(masked, false);
    lines[py_range(lines.len(), start - 1, end)]
        .iter()
        .filter(|l| !py::strip(l).is_empty())
        .count() as i64
}

re!(ELIXIR_HEAD, r"^(\s*)defp?\s+(?:self\.)?([\w?!=]+)");
re!(ELIXIR_ONE_LINE, r",\s*do:");

fn elixir_ruby_spans(masked: &Text) -> Vec<(String, usize, usize)> {
    let mut spans = Vec::new();
    let lines = py::splitlines(&masked.s, true);
    let mut offsets = vec![0usize];
    for line in &lines {
        offsets.push(offsets[offsets.len() - 1] + line.chars().count());
    }
    for (index, line) in lines.iter().enumerate() {
        let line_text = Text::new(line);
        let Some(head) = ELIXIR_HEAD.search(&line_text, 0) else {
            continue;
        };
        let name = head.group(&line_text, 2).unwrap_or("").to_string();
        if ELIXIR_ONE_LINE.is_match(line) {
            spans.push((name, offsets[index], offsets[index + 1]));
            continue;
        }
        let indent = head.group(&line_text, 1).unwrap_or("").chars().count();
        for other in index + 1..lines.len() {
            let candidate = lines[other];
            let leading = candidate.chars().count() - candidate.trim_start_matches(py::is_space).chars().count();
            if py::strip(candidate) == "end" && leading <= indent {
                spans.push((name, offsets[index], offsets[other + 1]));
                break;
            }
        }
    }
    spans
}

re!(GO_FUNCTION, r"(?m)\bfunc\s*(?:\([^)]*\)\s*)?([\w]*)\s*\(");
re!(RUST_FUNCTION, r"(?m)\bfn\s+(\w+)");
re!(
    TS_FUNCTION,
    r"(?m)\bfunction\s*\*?\s*([\w$]*)\s*\(|([\w$]+)\s*=\s*(?:async\s*)?(?:\([^()]*\)|[\w$]+)\s*(?::[^=;{]+)?=>\s*\{|^\s*(?:(?:public|private|protected|static|async|get|set)\s+)*([\w$]+)\s*\([^()]*\)\s*(?::[^{;]+)?\{"
);
re!(
    BRACE_FUNCTION,
    r"(?m)\b(?:fun|func|function|def)\s+(?:[\w.<>]+\.)?([\w$]+)|^[ \t]*(?:[\w<>\[\],.*&:~?]+[ \t]+)+([A-Za-z_]\w*)\s*\([^;{}]*\)[^;{}=]*\{"
);

fn brace_spans(masked: &Text, language: &str) -> Vec<(String, usize, usize)> {
    let pattern: &Re = match language {
        "go" => &GO_FUNCTION,
        "rust" => &RUST_FUNCTION,
        "typescript" => &TS_FUNCTION,
        _ => &BRACE_FUNCTION,
    };
    let mut spans = Vec::new();
    for found in pattern.iter(masked) {
        let Some(opening) = masked.find("{", found.end().saturating_sub(1)) else {
            continue;
        };
        if masked.sl(found.end(), opening).contains(';') {
            continue;
        }
        let name = (1..found.spans.len())
            .filter_map(|g| found.group(masked, g))
            .find(|g| !g.is_empty())
            .unwrap_or("<anonymous>")
            .to_string();
        if ["if", "for", "while", "switch", "catch", "function", "foreach"].contains(&name.as_str()) {
            continue;
        }
        spans.push((name, found.start(), matching_close(&masked.c, opening)));
    }
    spans
}

re!(GO_DECISION, r"\bif\b|\bfor\b|\bcase\b|&&|\|\|");
re!(RUST_DECISION, r"\bif\b|\bwhile\b|\bfor\b|=>|&&|\|\||\?(?![\w?])");
re!(
    TS_DECISION,
    r"\bif\b|\bfor\b|\bwhile\b|\bcase\b|\bcatch\b|&&|\|\||\?\?|\?\.|\?(?![.?])"
);
re!(ELIXIR_DECISION, r"\bif\b|\bunless\b|->|&&|\|\||\band\b|\bor\b");
re!(
    RUBY_DECISION,
    r"\b(?:if|unless|elsif|while|until|for|when|rescue)\b|&&|\|\||\band\b|\bor\b"
);
re!(
    BRACE_DECISION,
    r"\b(?:if|for|foreach|while|case|catch|when)\b|&&|\|\||\?\?|\?(?![.:?])"
);

fn decision_regex(language: &str) -> &'static Re {
    match language {
        "go" => &GO_DECISION,
        "rust" => &RUST_DECISION,
        "typescript" => &TS_DECISION,
        "elixir" => &ELIXIR_DECISION,
        "ruby" => &RUBY_DECISION,
        _ => &BRACE_DECISION,
    }
}

fn max_brace_depth(body: &str) -> i64 {
    let (mut depth, mut deepest) = (0i64, 0i64);
    for c in body.chars() {
        if c == '{' || c == '(' {
            depth += 1;
            deepest = deepest.max(depth);
        } else if c == '}' || c == ')' {
            depth -= 1;
        }
    }
    deepest
}

re!(MATCH_WORD, r"\bmatch\b");
re!(FN_WORD, r"\bfn\b");

fn span_metric(
    path: &str,
    masked: &Text,
    language: &str,
    decision: &Re,
    spans: &[(String, usize, usize)],
    (name, start, end): &(String, usize, usize),
) -> FunctionMetric {
    let mut body = masked.sl(*start, *end).to_string();
    for (_, inner_start, inner_end) in spans {
        if start < inner_start && inner_end <= end {
            body = body.replacen(masked.sl(*inner_start, *inner_end), "", 1);
        }
    }
    let mut count = decision.find_strs(&body).len() as i64;
    if language == "rust" {
        count -= MATCH_WORD.find_strs(&body).len() as i64;
    }
    if language == "elixir" {
        count -= FN_WORD.find_strs(&body).len() as i64;
    }
    let first = masked.newlines_before(*start) as i64 + 1;
    let last = masked.newlines_before((*start).max(end.saturating_sub(1))) as i64 + 1;
    FunctionMetric {
        path: path.to_string(),
        name: name.clone(),
        start: first,
        end: last,
        complexity: 1 + count.max(0),
        sloc: source_lines(&masked.s, first, last),
        nesting: (max_brace_depth(&body) - 1).max(0),
    }
}

/// Approximate complexity for Go, Rust, Elixir, Ruby, brace languages and JS/TS
/// without a compiler: functions found structurally on masked source.
fn masked_functions(path: &str, text: &str, language: &str) -> Result<Vec<FunctionMetric>, CheckError> {
    let masked = slop_mask(language, &Text::new(text))?;
    let spans = if language == "elixir" || language == "ruby" {
        elixir_ruby_spans(&masked)
    } else {
        brace_spans(&masked, language)
    };
    let decision = decision_regex(language);
    let results = spans
        .iter()
        .map(|span| span_metric(path, &masked, language, decision, &spans, span))
        .collect();
    Ok(results)
}

/// Exact metrics when a parser supplied them, else structural approximation.
fn function_metrics(
    path: &str,
    text: &str,
    exact: Option<&Vec<FunctionMetric>>,
) -> Result<Vec<FunctionMetric>, CheckError> {
    let language = slop_language(path);
    if language == Some("python") {
        return pyast::python_functions(path, text);
    }
    if let Some(exact) = exact {
        return Ok(exact.clone());
    }
    match language {
        None => Ok(vec![]),
        Some(language) => masked_functions(path, text, language),
    }
}

const SLOP_TYPESCRIPT: &str = r#"
const ts = require(process.argv[1]);
const files = JSON.parse(require('node:fs').readFileSync(0, 'utf8'));
const decision = new Set([ts.SyntaxKind.IfStatement, ts.SyntaxKind.ForStatement,
  ts.SyntaxKind.ForInStatement, ts.SyntaxKind.ForOfStatement,
  ts.SyntaxKind.WhileStatement, ts.SyntaxKind.DoStatement, ts.SyntaxKind.CaseClause,
  ts.SyntaxKind.CatchClause, ts.SyntaxKind.ConditionalExpression]);
const logical = new Set([ts.SyntaxKind.AmpersandAmpersandToken,
  ts.SyntaxKind.BarBarToken, ts.SyntaxKind.QuestionQuestionToken]);
const nesting = new Set([ts.SyntaxKind.IfStatement, ts.SyntaxKind.ForStatement,
  ts.SyntaxKind.ForInStatement, ts.SyntaxKind.ForOfStatement,
  ts.SyntaxKind.WhileStatement, ts.SyntaxKind.DoStatement,
  ts.SyntaxKind.SwitchStatement, ts.SyntaxKind.TryStatement]);
const out = {};
for (const [name, text] of Object.entries(files)) {
  const file = ts.createSourceFile(name, text, ts.ScriptTarget.Latest, true);
  const functions = [];
  const measure = (fn, label) => {
    let complexity = 1, deepest = 0;
    const walk = (node, depth) => {
      if (node !== fn && ts.isFunctionLike(node)) return;
      if (decision.has(node.kind)) complexity++;
      if (ts.isBinaryExpression(node) && logical.has(node.operatorToken.kind)) complexity++;
      if ((ts.isPropertyAccessExpression(node) || ts.isElementAccessExpression(node) ||
           ts.isCallExpression(node)) && node.questionDotToken) complexity++;
      const next = nesting.has(node.kind) ? depth + 1 : depth;
      deepest = Math.max(deepest, next);
      ts.forEachChild(node, child => walk(child, next));
    };
    ts.forEachChild(fn, child => walk(child, 0));
    const start = file.getLineAndCharacterOfPosition(fn.getStart(file)).line + 1;
    const end = file.getLineAndCharacterOfPosition(fn.getEnd()).line + 1;
    functions.push([label, start, end, complexity, deepest]);
  };
  const visit = node => {
    if (ts.isFunctionLike(node) && node.body) {
      const label = node.name && ts.isIdentifier(node.name) ? node.name.text
        : ts.isVariableDeclaration(node.parent) && ts.isIdentifier(node.parent.name)
          ? node.parent.name.text : '<anonymous>';
      measure(node, label);
    }
    ts.forEachChild(node, visit);
  };
  visit(file);
  out[name] = functions;
}
console.log(JSON.stringify(out));
"#;

const SLOP_GO: &str = r#"package main

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
)

type function struct {
	Name       string `json:"name"`
	Start      int    `json:"start"`
	End        int    `json:"end"`
	Complexity int    `json:"complexity"`
	Nesting    int    `json:"nesting"`
}

func nests(node ast.Node) bool {
	switch node.(type) {
	case *ast.IfStmt, *ast.ForStmt, *ast.RangeStmt, *ast.SwitchStmt,
		*ast.TypeSwitchStmt, *ast.SelectStmt:
		return true
	}
	return false
}

// measure counts gocyclo decisions; function literals are measured separately.
func measure(fset *token.FileSet, root ast.Node, body *ast.BlockStmt, name string,
	out *[]function) {
	complexity, deepest := 1, 0
	var stack []ast.Node
	ast.Inspect(body, func(node ast.Node) bool {
		if node == nil {
			stack = stack[:len(stack)-1]
			return true
		}
		if literal, ok := node.(*ast.FuncLit); ok {
			measure(fset, literal, literal.Body, "<anonymous>", out)
			return false
		}
		stack = append(stack, node)
		switch item := node.(type) {
		case *ast.IfStmt, *ast.ForStmt, *ast.RangeStmt:
			complexity++
		case *ast.CaseClause:
			if item.List != nil {
				complexity++
			}
		case *ast.CommClause:
			if item.Comm != nil {
				complexity++
			}
		case *ast.BinaryExpr:
			if item.Op == token.LAND || item.Op == token.LOR {
				complexity++
			}
		}
		depth := 0
		for _, open := range stack {
			if nests(open) {
				depth++
			}
		}
		if depth > deepest {
			deepest = depth
		}
		return true
	})
	*out = append(*out, function{name, fset.Position(root.Pos()).Line,
		fset.Position(root.End()).Line, complexity, deepest})
}

func main() {
	var files map[string]string
	if err := json.NewDecoder(os.Stdin).Decode(&files); err != nil {
		os.Exit(2)
	}
	result := map[string][]function{}
	for name, text := range files {
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, name, text, parser.SkipObjectResolution)
		functions := []function{}
		if err == nil {
			for _, declaration := range file.Decls {
				item, ok := declaration.(*ast.FuncDecl)
				if !ok || item.Body == nil {
					continue
				}
				label := item.Name.Name
				if item.Recv != nil && len(item.Recv.List) == 1 {
					receiver := item.Recv.List[0].Type
					if star, ok := receiver.(*ast.StarExpr); ok {
						receiver = star.X
					}
					if ident, ok := receiver.(*ast.Ident); ok {
						label = ident.Name + "." + label
					}
				}
				measure(fset, item, item.Body, label, &functions)
			}
		}
		result[name] = functions
	}
	json.NewEncoder(os.Stdout).Encode(result)
}
"#;

const SLOP_ELIXIR: &str = r##"
defmodule LokiSlop do
  @branches [:if, :unless]
  @clauses [:case, :cond, :receive]
  @nesting [:if, :unless, :case, :cond, :receive, :with, :try, :fn]
  @boolean [:and, :or, :&&, :||]
  @definitions [:def, :defp, :defmacro, :defmacrop]

  def main do
    # A file, not stdin: unicode-mode stdio rejects sources with non-Latin-1 text.
    [path] = System.argv()
    read(File.read!(path))
  end

  defp read(""), do: :ok

  defp read(data) do
    [name, rest] = :binary.split(data, "\n")
    [size, rest] = :binary.split(rest, "\n")
    count = String.to_integer(size)
    <<text::binary-size(count), rest::binary>> = rest
    measure(name, text)
    read(rest)
  end

  defp measure(name, text) do
    case Code.string_to_quoted(text, token_metadata: true) do
      {:ok, ast} ->
        Macro.prewalk(ast, nil, fn
          {kind, meta, [head | body]} = node, acc when kind in @definitions ->
            emit(name, head, meta, body)
            {node, acc}

          node, acc ->
            {node, acc}
        end)

      _ ->
        IO.puts("#{name}\tUNPARSED")
    end
  end

  defp label({:when, _, [call | _]}), do: label(call)
  defp label({name, _, _}) when is_atom(name), do: Atom.to_string(name)
  defp label(_), do: "<anonymous>"

  defp emit(name, head, meta, body) do
    start = Keyword.get(meta, :line, 0)
    finish = get_in(meta, [:end, :line]) || last_line(body, start)
    {complexity, nesting} = walk(body, 0)
    IO.puts(Enum.join([name, label(head), start, finish, 1 + complexity, nesting], "\t"))
  end

  defp last_line(node, line) do
    {_, found} =
      Macro.prewalk(node, line, fn
        {_, meta, _} = item, acc when is_list(meta) -> {item, max(acc, meta[:line] || acc)}
        item, acc -> {item, acc}
      end)

    found
  end

  # Returns {decisions, deepest nesting} for a subtree.
  defp walk({kind, _, args}, depth) when is_atom(kind) and is_list(args) do
    own =
      cond do
        kind in @branches -> 1
        kind in @clauses -> max(length(arms(args)) - 1, 0)
        kind == :with -> Enum.count(args, &match?({:<-, _, _}, &1)) + length(arms(args, :else))
        kind == :try -> length(arms(args, :rescue)) + length(arms(args, :catch))
        kind == :fn -> max(length(args) - 1, 0)
        kind in @boolean and length(args) == 2 -> 1
        true -> 0
      end

    inner = if kind in @nesting, do: depth + 1, else: depth
    {count, deepest} = walk(args, inner)
    {own + count, max(deepest, if(kind in @nesting, do: inner, else: depth))}
  end

  defp walk({left, right}, depth), do: walk([left, right], depth)

  defp walk(list, depth) when is_list(list) do
    Enum.reduce(list, {0, depth}, fn item, {count, deepest} ->
      {inner, reached} = walk(item, depth)
      {count + inner, max(deepest, reached)}
    end)
  end

  defp walk({callee, _, args}, depth) when is_list(args), do: walk([callee | args], depth)
  defp walk(_, depth), do: {0, depth}

  defp arms(args, key \\ :do) do
    Enum.find_value(args, [], fn
      list when is_list(list) ->
        case Keyword.get(list, key) do
          clauses when is_list(clauses) -> Enum.filter(clauses, &match?({:->, _, _}, &1))
          _ -> nil
        end

      _ ->
        nil
    end)
  end
end

LokiSlop.main()
"##;

type Metrics = HashMap<String, Vec<FunctionMetric>>;

fn json_object(texts: &[(String, String)]) -> Value {
    Value::Object(
        texts
            .iter()
            .map(|(k, v)| (k.clone(), Value::String(v.clone())))
            .collect(),
    )
}

type MetricExtractor = fn(&Value) -> Option<(String, i64, i64, i64, i64)>;

fn parse_json_metrics(
    report: &Value,
    texts: &[(String, String)],
    mask: fn(&Text) -> Text,
    extract: MetricExtractor,
) -> Option<Metrics> {
    let lookup: HashMap<&str, &str> = texts.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    let mut metrics = HashMap::new();
    for (name, functions) in report.as_object()? {
        let masked = mask(&Text::new(lookup.get(name.as_str())?));
        let mut list = Vec::new();
        for item in functions.as_array()? {
            let (fn_name, start, end, complexity, nesting) = extract(item)?;
            list.push(FunctionMetric {
                path: name.clone(),
                name: fn_name,
                start,
                end,
                complexity,
                sloc: source_lines(&masked.s, start, end),
                nesting,
            });
        }
        metrics.insert(name.clone(), list);
    }
    Some(metrics)
}

fn extract_ts_metric(item: &Value) -> Option<(String, i64, i64, i64, i64)> {
    Some((
        item[0].as_str()?.to_string(),
        item[1].as_i64()?,
        item[2].as_i64()?,
        item[3].as_i64()?,
        item[4].as_i64()?,
    ))
}

fn extract_go_metric(item: &Value) -> Option<(String, i64, i64, i64, i64)> {
    Some((
        item["name"].as_str()?.to_string(),
        item["start"].as_i64()?,
        item["end"].as_i64()?,
        item["complexity"].as_i64()?,
        item["nesting"].as_i64()?,
    ))
}

fn typescript_function_metrics(root: &Path, texts: &[(String, String)], deadline: Deadline) -> Option<Metrics> {
    let compiler = crate::typescript::typescript_compiler(root)?;
    if texts.is_empty() {
        return None;
    }
    let command = vec![
        "node".to_string(),
        "-e".into(),
        SLOP_TYPESCRIPT.into(),
        resolve(&compiler).to_string_lossy().into_owned(),
    ];
    let input = py::dumps(&json_object(texts));
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/"));
    let result = proc::run(&command, &cwd, Some(input.as_bytes()), &[], deadline.timeout().ok()?).ok()?;
    if result.code != 0 {
        return None;
    }
    let report: Value = serde_json::from_str(&proc::text(&result.stdout)).ok()?;
    parse_json_metrics(&report, texts, mask_javascript, extract_ts_metric)
}

fn home() -> PathBuf {
    PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| "/".into()))
}

fn ensure_go_metrics_tool(deadline: Deadline) -> Option<PathBuf> {
    let digest = crate::compat::sha256_hex(SLOP_GO.as_bytes());
    let tool = home()
        .join(".cache/loki/tools")
        .join(format!("gometrics-{}", &digest[..16]));
    if !tool.is_file() {
        let source = tool.with_extension("src");
        std::fs::create_dir_all(&source).ok()?;
        std::fs::write(source.join("go.mod"), "module lokimetrics\n\ngo 1.21\n").ok()?;
        std::fs::write(source.join("main.go"), SLOP_GO).ok()?;
        let command = vec![
            "go".to_string(),
            "build".into(),
            "-o".into(),
            tool.to_string_lossy().into_owned(),
            ".".into(),
        ];
        let built = proc::run(
            &command,
            &source,
            None,
            &[("GOTOOLCHAIN", "local"), ("GOFLAGS", "-mod=mod")],
            deadline.timeout().ok()?,
        )
        .ok()?;
        if built.code != 0 {
            return None;
        }
    }
    Some(tool)
}

fn go_function_metrics(texts: &[(String, String)], deadline: Deadline) -> Option<Metrics> {
    if texts.is_empty() || proc::which("go").is_none() {
        return None;
    }
    let tool = ensure_go_metrics_tool(deadline)?;
    let input = py::dumps(&json_object(texts));
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/"));
    let result = proc::run(
        &[tool.to_string_lossy().into_owned()],
        &cwd,
        Some(input.as_bytes()),
        &[],
        deadline.timeout().ok()?,
    )
    .ok()?;
    if result.code != 0 {
        return None;
    }
    let report: Value = serde_json::from_str(&String::from_utf8(result.stdout).ok()?).ok()?;
    parse_json_metrics(&report, texts, mask_rust, extract_go_metric)
}

fn parse_elixir_metrics(stdout: &[u8], texts: &[(String, String)]) -> Option<Metrics> {
    let lookup: HashMap<&str, &str> = texts.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    let mut metrics: Metrics = texts.iter().map(|(name, _)| (name.clone(), vec![])).collect();
    let mut masks: HashMap<String, Text> = HashMap::new();
    for line in py::splitlines(&String::from_utf8_lossy(stdout), false) {
        let fields: Vec<&str> = line.split('\t').collect();
        if fields.len() != 6 || !lookup.contains_key(fields[0]) {
            continue;
        }
        let numbers: Vec<i64> = fields[2..]
            .iter()
            .map(|f| py::strip(f).parse().ok())
            .collect::<Option<_>>()?;
        let masked = masks
            .entry(fields[0].to_string())
            .or_insert_with(|| mask_elixir(&Text::new(lookup[fields[0]])));
        let sloc = source_lines(&masked.s, numbers[0], numbers[1]);
        metrics.get_mut(fields[0])?.push(FunctionMetric {
            path: fields[0].to_string(),
            name: fields[1].to_string(),
            start: numbers[0],
            end: numbers[1],
            complexity: numbers[2],
            sloc,
            nesting: numbers[3],
        });
    }
    Some(metrics)
}

fn elixir_function_metrics(texts: &[(String, String)], deadline: Deadline) -> Option<Metrics> {
    if texts.is_empty() || proc::which("elixir").is_none() {
        return None;
    }
    let payload: String = texts
        .iter()
        .map(|(name, text)| format!("{name}\n{}\n{text}", text.len()))
        .collect();
    let handle = tempfile::Builder::new().suffix(".loki").tempfile().ok()?;
    std::fs::write(handle.path(), payload.as_bytes()).ok()?;
    let command = vec![
        "elixir".to_string(),
        "-e".into(),
        SLOP_ELIXIR.into(),
        handle.path().to_string_lossy().into_owned(),
    ];
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/"));
    let result = proc::run(&command, &cwd, None, &[], deadline.timeout().ok()?).ok()?;
    if result.code != 0 {
        return None;
    }
    parse_elixir_metrics(&result.stdout, texts)
}

/// Parser-backed metrics for TS/JS, Go and Elixir, plus languages left approximate.
fn exact_function_metrics(root: &Path, texts: &[(String, String)], deadline: Deadline) -> (Metrics, BTreeSet<String>) {
    let mut exact = HashMap::new();
    let mut approximate = BTreeSet::new();
    for language in ["typescript", "go", "elixir"] {
        let chosen: Vec<(String, String)> = texts
            .iter()
            .filter(|(path, _)| slop_language(path) == Some(language))
            .cloned()
            .collect();
        if chosen.is_empty() {
            continue;
        }
        let result = match language {
            "typescript" => typescript_function_metrics(root, &chosen, deadline),
            "go" => go_function_metrics(&chosen, deadline),
            _ => elixir_function_metrics(&chosen, deadline),
        };
        match result {
            None => {
                approximate.insert(language.to_string());
            }
            Some(found) => exact.extend(found),
        }
    }
    for (path, _) in texts {
        if let Some(language) = slop_language(path)
            && !EXACT_COMPLEXITY.contains(&language)
        {
            approximate.insert(language.to_string());
        }
    }
    (exact, approximate)
}

fn is_word(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

fn scan_token(c: &[char], start: usize) -> Option<(usize, bool)> {
    let ch = c[start];
    if ch.is_ascii_alphabetic() || ch == '_' {
        let end = (start + 1..c.len()).find(|&i| !is_word(c[i])).unwrap_or(c.len());
        return Some((end, false));
    }
    if ch.is_numeric() {
        let end = (start + 1..c.len())
            .find(|&i| !is_word(c[i]) && c[i] != '.')
            .unwrap_or(c.len());
        return Some((end, false));
    }
    if matches!(ch, '"' | '\'' | '`')
        && let Some(close) = (start + 1..c.len()).find(|&j| !py::is_space(c[j]))
        && c[close] == ch
    {
        return Some((close + 1, true));
    }
    (!py::is_space(ch)).then_some((start + 1, false))
}

fn classify_token(c: &[char], start: usize, end: usize, quoted: bool, keywords: &HashSet<&str>) -> String {
    let first = c[start];
    if first.is_alphabetic() || first == '_' {
        let symbol: String = c[start..end].iter().collect();
        if keywords.contains(symbol.as_str()) {
            return symbol;
        }
        return "I".into();
    }
    if first.is_numeric() {
        return "N".into();
    }
    if quoted {
        return "S".into();
    }
    c[start..end].iter().collect()
}

/// Tokens with identifiers and literals replaced by placeholders, per line.
fn normalized_tokens(path: &str, text: &str) -> Result<Vec<(String, i64)>, CheckError> {
    let Some(language) = slop_language(path) else {
        return Ok(vec![]);
    };
    let masked = slop_mask(language, &Text::new(text))?;
    let family = if BRACE_LANGUAGES.contains(&language) {
        "brace"
    } else {
        language
    };
    let keywords: HashSet<&str> = keywords(family).split(' ').collect();
    let c = &masked.c;
    let mut tokens = Vec::new();
    let (mut line, mut i) = (1i64, 0usize);
    while i < c.len() {
        if c[i] == '\n' {
            line += 1;
            i += 1;
            continue;
        }
        let start = i;
        if let Some((end, quoted)) = scan_token(c, start) {
            i = end;
            // Only a bare newline token advances the line, as in loki.py.
            tokens.push((classify_token(c, start, end, quoted, &keywords), line));
        } else {
            i += 1;
        }
    }
    Ok(tokens)
}

static TOKEN_CODES: LazyLock<Mutex<HashMap<String, u64>>> = LazyLock::new(Default::default);

type Windows = (Vec<(String, i64)>, Vec<u64>);

/// Normalized tokens and rolling hashes of every 100-token window.
fn token_windows(path: &str, text: &str) -> Result<Windows, CheckError> {
    const MODULUS: u128 = (1 << 61) - 1;
    const BASE: u128 = 1_000_003;
    let mut power: u128 = 1;
    for _ in 0..CLONE_MIN_TOKENS - 1 {
        power = power * BASE % MODULUS;
    }
    let tokens = normalized_tokens(path, text)?;
    let codes: Vec<u128> = {
        let mut table = TOKEN_CODES
            .lock()
            .map_err(|_| CheckError::Value("token table poisoned".into()))?;
        tokens
            .iter()
            .map(|(token, _)| {
                let next = table.len() as u64 + 1;
                *table.entry(token.clone()).or_insert(next) as u128
            })
            .collect()
    };
    let mut hashes = Vec::new();
    let mut value: u128 = 0;
    for (index, code) in codes.iter().enumerate() {
        if index >= CLONE_MIN_TOKENS {
            let drop = codes[index - CLONE_MIN_TOKENS] * power % MODULUS;
            value = (value + MODULUS - drop) % MODULUS;
        }
        value = (value * BASE + code) % MODULUS;
        if index + 1 >= CLONE_MIN_TOKENS {
            hashes.push(value as u64);
        }
    }
    Ok((tokens, hashes))
}

type Span = (String, i64, i64);
/// Cloned lines per file, and each clone group's member spans.
type Clones = (BTreeMap<String, BTreeSet<i64>>, Vec<Vec<Span>>);

fn collect_duplicate_windows(
    indexed: &[(String, Windows)],
    wanted: Option<&HashSet<u64>>,
) -> Vec<Vec<(String, usize)>> {
    let mut windows: Vec<(u64, Vec<(String, usize)>)> = Vec::new();
    let mut slot: HashMap<u64, usize> = HashMap::new();
    for (path, (_, hashes)) in indexed {
        for (index, value) in hashes.iter().enumerate() {
            if wanted.is_none_or(|w| w.contains(value)) {
                let at = *slot.entry(*value).or_insert_with(|| {
                    windows.push((*value, Vec::new()));
                    windows.len() - 1
                });
                windows[at].1.push((path.clone(), index));
            }
        }
    }
    windows
        .into_iter()
        .map(|(_, positions)| positions)
        .filter(|positions| positions.len() > 1)
        .collect()
}

type TokenRuns = (Vec<(String, usize, usize)>, HashMap<(String, usize), usize>);

fn build_token_runs(duplicates: &[Vec<(String, usize)>]) -> TokenRuns {
    let mut covered_tokens: Vec<(String, BTreeSet<usize>)> = Vec::new();
    for positions in duplicates {
        for (path, index) in positions {
            let entry = match covered_tokens.iter().position(|(p, _)| p == path) {
                Some(i) => i,
                None => {
                    covered_tokens.push((path.clone(), BTreeSet::new()));
                    covered_tokens.len() - 1
                }
            };
            covered_tokens[entry].1.extend(*index..index + CLONE_MIN_TOKENS);
        }
    }
    let mut run_of: HashMap<(String, usize), usize> = HashMap::new();
    let mut runs: Vec<(String, usize, usize)> = Vec::new();
    for (path, indexes) in &covered_tokens {
        for &index in indexes {
            let previous = index
                .checked_sub(1)
                .and_then(|p| run_of.get(&(path.clone(), p)).copied());
            let run = match previous {
                Some(run) => {
                    runs[run].2 = index;
                    run
                }
                None => {
                    runs.push((path.clone(), index, index));
                    runs.len() - 1
                }
            };
            run_of.insert((path.clone(), index), run);
        }
    }
    (runs, run_of)
}

fn dsu_find(parent: &mut [usize], mut item: usize) -> usize {
    while parent[item] != item {
        parent[item] = parent[parent[item]];
        item = parent[item];
    }
    item
}

fn group_run_components(
    runs_len: usize,
    duplicates: &[Vec<(String, usize)>],
    run_of: &HashMap<(String, usize), usize>,
) -> Vec<(usize, Vec<usize>)> {
    let mut parent: Vec<usize> = (0..runs_len).collect();
    for positions in duplicates {
        let first = dsu_find(&mut parent, run_of[&positions[0]]);
        for position in &positions[1..] {
            let root = dsu_find(&mut parent, run_of[position]);
            parent[root] = first;
        }
    }
    let mut components: Vec<(usize, Vec<usize>)> = Vec::new();
    for run in 0..runs_len {
        let root = dsu_find(&mut parent, run);
        match components.iter_mut().find(|(r, _)| *r == root) {
            Some((_, members)) => members.push(run),
            None => components.push((root, vec![run])),
        }
    }
    components
}

fn collect_clone_spans(
    components: Vec<(usize, Vec<usize>)>,
    runs: &[(String, usize, usize)],
    streams: &HashMap<&str, &Vec<(String, i64)>>,
    focus: Option<&HashSet<String>>,
) -> Clones {
    let mut covered: BTreeMap<String, BTreeSet<i64>> = BTreeMap::new();
    let mut spans: Vec<Vec<Span>> = Vec::new();
    for (_, members) in components {
        if members.len() < 2 {
            continue;
        }
        let mut lines: Vec<Span> = Vec::new();
        for run in members {
            let (path, first, last) = &runs[run];
            let tokens = streams[path.as_str()];
            lines.push((path.clone(), tokens[*first].1, tokens[*last].1));
        }
        if lines.iter().all(|(_, start, end)| end - start + 1 < CLONE_MIN_LINES) {
            continue;
        }
        if let Some(focus) = focus
            && !lines.iter().any(|(path, _, _)| focus.contains(path))
        {
            continue;
        }
        for (path, start, end) in &lines {
            covered.entry(path.clone()).or_default().extend(*start..=*end);
        }
        lines.sort();
        spans.push(lines);
    }
    spans.sort();
    (covered, spans)
}

/// Normalized-token clones of at least 100 tokens and 3 lines.
fn clone_lines(files: &[(String, String)], focus: Option<&HashSet<String>>) -> Result<Clones, CheckError> {
    let python: Vec<&str> = files
        .iter()
        .filter(|(p, _)| slop_language(p) == Some("python"))
        .map(|(_, t)| t.as_str())
        .collect();
    if !python.is_empty() {
        pyast::prefetch_tokens(&python)?;
    }
    let mut indexed: Vec<(String, Windows)> = Vec::new();
    for (path, text) in files {
        indexed.push((path.clone(), token_windows(path, text)?));
    }
    let wanted: Option<HashSet<u64>> = focus.map(|focus| {
        indexed
            .iter()
            .filter(|(p, _)| focus.contains(p))
            .flat_map(|(_, w)| w.1.iter().copied())
            .collect()
    });
    if let (Some(focus), Some(wanted)) = (focus, &wanted) {
        indexed.retain(|(path, (_, hashes))| focus.contains(path) || hashes.iter().any(|h| wanted.contains(h)));
    }
    let streams: HashMap<&str, &Vec<(String, i64)>> = indexed.iter().map(|(p, (t, _))| (p.as_str(), t)).collect();
    let duplicates = collect_duplicate_windows(&indexed, wanted.as_ref());
    let (runs, run_of) = build_token_runs(&duplicates);
    let components = group_run_components(runs.len(), &duplicates, &run_of);
    Ok(collect_clone_spans(components, &runs, &streams, focus))
}

/// `os.path.normpath` for relative POSIX paths.
pub(crate) fn normpath(path: &str) -> String {
    let absolute = path.starts_with('/');
    let mut parts: Vec<&str> = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." if parts.last().is_some_and(|p| *p != "..") => {
                parts.pop();
            }
            ".." if absolute => {}
            other => parts.push(other),
        }
    }
    let joined = parts.join("/");
    match (absolute, joined.is_empty()) {
        (true, _) => format!("/{joined}"),
        (false, true) => ".".into(),
        (false, false) => joined,
    }
}

fn python_module_map(files: &[(String, String)]) -> Vec<(String, String)> {
    let mut modules: Vec<(String, String)> = Vec::new();
    for (path, _) in files.iter().filter(|(p, _)| p.ends_with(".py")) {
        let filename = path.rsplit('/').next().unwrap_or(path);
        let stem = if filename == ".py" {
            path.as_str()
        } else {
            path.strip_suffix(".py").unwrap_or(path)
        };
        let mut module = stem.replace('/', ".");
        if let Some(stripped) = module.strip_suffix(".__init__") {
            module = stripped.to_string();
        }
        match modules.iter_mut().find(|(m, _)| *m == module) {
            Some(entry) => entry.1 = path.clone(),
            None => modules.push((module, path.clone())),
        }
    }
    modules
}

fn resolve_python_import(package: &str, level: Option<i64>, base: String, aliases: Vec<String>) -> Vec<String> {
    let Some(level) = level else {
        return aliases;
    };
    let mut base = base;
    if level != 0 {
        let parts: Vec<&str> = package.split('.').collect();
        let mut keep: Vec<&str> = parts[py_range(parts.len(), 0, parts.len() as i64 - level + 1)].to_vec();
        let tail = base.clone();
        if !tail.is_empty() {
            keep.push(&tail);
        }
        base = keep.join(".");
    }
    std::iter::once(base.clone())
        .chain(aliases.iter().map(|a| format!("{base}.{a}")))
        .collect()
}

fn python_import_graph(files: &[(String, String)]) -> Result<BTreeMap<String, BTreeSet<String>>, CheckError> {
    let modules = python_module_map(files);
    let lookup: HashMap<&str, &str> = modules.iter().map(|(m, p)| (m.as_str(), p.as_str())).collect();
    let texts: HashMap<&str, &str> = files.iter().map(|(p, t)| (p.as_str(), t.as_str())).collect();
    pyast::prefetch(&modules.iter().map(|(_, p)| texts[p.as_str()]).collect::<Vec<_>>())?;
    let mut graph = BTreeMap::new();
    for (module, path) in &modules {
        let package = if path.ends_with("__init__.py") {
            module.clone()
        } else {
            module
                .rsplit_once('.')
                .map_or(module.clone(), |(head, _)| head.to_string())
        };
        let mut edges = BTreeSet::new();
        for (level, base, aliases) in pyast::python_imports(path, texts[path.as_str()])? {
            for name in resolve_python_import(&package, level, base, aliases) {
                if let Some(target) = lookup.get(name.as_str())
                    && target != path
                {
                    edges.insert(target.to_string());
                }
            }
        }
        graph.insert(path.clone(), edges);
    }
    Ok(graph)
}

re!(
    JS_IMPORT,
    r#"(?m)^\s*(?:import|export)(?!\s+type\b)[^;'"]*?from\s*(['"])(\.{1,2}/[^'"]+)\1|^\s*import\s*(['"])(\.{1,2}/[^'"]+)\3"#
);
re!(JS_EXTENSION, r"\.(?:js|mjs|cjs)$");

fn javascript_import_graph(files: &[(String, String)]) -> BTreeMap<String, BTreeSet<String>> {
    let names: HashSet<&str> = files.iter().map(|(p, _)| p.as_str()).collect();
    let suffixes = [
        "",
        ".ts",
        ".tsx",
        ".js",
        ".jsx",
        ".mts",
        ".mjs",
        "/index.ts",
        "/index.js",
    ];
    let mut graph = BTreeMap::new();
    for (path, text) in files {
        if crate::rules::language(path) != Some("typescript") {
            continue;
        }
        let text = Text::new(text);
        let mut edges = BTreeSet::new();
        for found in JS_IMPORT.iter(&text) {
            let specifier = found.group(&text, 2).or_else(|| found.group(&text, 4)).unwrap_or("");
            let directory = path.rsplit_once('/').map_or("", |(d, _)| d);
            let joined = if directory.is_empty() {
                specifier.to_string()
            } else {
                format!("{directory}/{specifier}")
            };
            let base = normpath(&joined);
            let base = match JS_EXTENSION.search(&Text::new(&base), 0) {
                Some(m) => base.chars().take(m.start()).collect(),
                None => base,
            };
            let target = suffixes
                .iter()
                .map(|s| format!("{base}{s}"))
                .find(|c| names.contains(c.as_str()));
            if let Some(target) = target
                && target != *path
            {
                edges.insert(target);
            }
        }
        graph.insert(path.clone(), edges);
    }
    graph
}

re!(EX_DEFMODULE, r"(?m)^\s*defmodule\s+([\w.]+)");
re!(EX_REQUIRE, r"(?m)^\s*(?:import|use|require)\s+([\w.]+)");

fn elixir_source(path: &str) -> bool {
    let name = path.rsplit('/').next().unwrap_or(path);
    matches!(name.rfind('.'), Some(i) if i > 0 && (&name[i..] == ".ex" || &name[i..] == ".exs"))
}

fn elixir_import_graph(files: &[(String, String)]) -> BTreeMap<String, BTreeSet<String>> {
    let mut owners: HashMap<String, String> = HashMap::new();
    let mut masks: HashMap<&str, Text> = HashMap::new();
    for (path, text) in files.iter().filter(|(p, _)| elixir_source(p)) {
        let masked = mask_elixir(&Text::new(text));
        for module in EX_DEFMODULE.group1_strs(&masked.s) {
            owners.insert(module.to_string(), path.clone());
        }
        masks.insert(path, masked);
    }
    let mut graph = BTreeMap::new();
    for (path, _) in files.iter().filter(|(p, _)| elixir_source(p)) {
        let targets = EX_REQUIRE
            .group1_strs(&masks[path.as_str()].s)
            .into_iter()
            .map(String::from)
            .collect::<Vec<_>>();
        let edges = targets
            .iter()
            .filter_map(|t| owners.get(t))
            .filter(|o| *o != path)
            .cloned()
            .collect();
        graph.insert(path.clone(), edges);
    }
    graph
}

#[derive(Default)]
struct Tarjan<'a> {
    index: HashMap<&'a str, usize>,
    low: HashMap<&'a str, usize>,
    stack: Vec<&'a str>,
    on_stack: HashSet<&'a str>,
    cycles: Vec<Vec<String>>,
    counter: usize,
}

impl<'a> Tarjan<'a> {
    fn push_node(&mut self, node: &'a str) {
        self.index.insert(node, self.counter);
        self.low.insert(node, self.counter);
        self.counter += 1;
        self.stack.push(node);
        self.on_stack.insert(node);
    }

    fn pop_component(&mut self, node: &'a str) {
        let mut component = Vec::new();
        while let Some(item) = self.stack.pop() {
            self.on_stack.remove(item);
            component.push(item.to_string());
            if item == node {
                break;
            }
        }
        if component.len() > 1 {
            component.sort();
            self.cycles.push(component);
        }
    }

    fn visit_from(&mut self, graph: &'a BTreeMap<String, BTreeSet<String>>, start: &'a str) {
        let edges_of = |node: &str| {
            graph
                .get(node)
                .into_iter()
                .flat_map(|s| s.iter().map(String::as_str))
                .collect::<Vec<_>>()
        };
        let mut work: Vec<(&'a str, Vec<&'a str>, usize)> = vec![(start, edges_of(start), 0)];
        self.push_node(start);
        while let Some(top) = work.len().checked_sub(1) {
            let node = work[top].0;
            let mut advanced = false;
            while work[top].2 < work[top].1.len() {
                let target = work[top].1[work[top].2];
                work[top].2 += 1;
                if !self.index.contains_key(target) {
                    self.push_node(target);
                    work.push((target, edges_of(target), 0));
                    advanced = true;
                    break;
                }
                if self.on_stack.contains(target) {
                    let value = self.low[node].min(self.index[target]);
                    self.low.insert(node, value);
                }
            }
            if advanced {
                continue;
            }
            work.pop();
            if let Some(parent) = work.last() {
                let value = self.low[parent.0].min(self.low[node]);
                self.low.insert(parent.0, value);
            }
            if self.low[node] == self.index[node] {
                self.pop_component(node);
            }
        }
    }
}

/// Strongly connected components with more than one module, sorted.
fn import_cycles(graph: &BTreeMap<String, BTreeSet<String>>) -> Vec<Vec<String>> {
    let mut state = Tarjan::default();
    for start in graph.keys().map(String::as_str) {
        if !state.index.contains_key(start) {
            state.visit_from(graph, start);
        }
    }
    state.cycles.sort();
    state.cycles
}

re!(
    TS_VERBOSE,
    r"\bif\s*\([^()]*\)\s*\{?\s*return\s+(true|false)\s*;?\s*\}?\s*else\s*\{?\s*return\s+(true|false)\s*;?\s*\}?|[!=]==?\s*(?:true|false)\b"
);
re!(TS_CODE_COMMENT, r"[;{}]\s*$|^//\s*(?:const|let|return|if|await)\b");

/// Lines matching handcrafted verbosity heuristics.
fn verbose_lines(path: &str, text: &str) -> Result<BTreeSet<i64>, CheckError> {
    match crate::rules::language(path) {
        Some("python") => pyast::python_verbose_lines(text),
        Some("typescript") => {
            let mut flagged = BTreeSet::new();
            let masked = mask_javascript(&Text::new(text));
            for found in TS_VERBOSE.iter(&masked) {
                let first = masked.newlines_before(found.start()) as i64 + 1;
                let extra = found.whole(&masked).matches('\n').count() as i64;
                flagged.extend(first..=first + extra);
            }
            for (number, line) in py::splitlines(text, false).iter().enumerate() {
                let stripped = py::strip(line);
                if stripped.starts_with("//") && TS_CODE_COMMENT.is_match(stripped) {
                    flagged.insert(number as i64 + 1);
                }
            }
            Ok(flagged)
        }
        _ => Ok(BTreeSet::new()),
    }
}

fn saturate(value: f64, saturation: f64) -> f64 {
    100.0 * (value / saturation).min(1.0)
}

fn count_points(count: f64, scale: f64) -> f64 {
    let blend = (1.0 + count / scale).ln();
    100.0 * blend / (1.0 + blend)
}

re!(GENERATED, r"\.(?:min|generated|pb|g)\.[\w]+$|_pb2\.py$");

/// Vendored, generated, build-output and Loki-owned code is not project debt.
pub(crate) fn slop_included(path: &str) -> bool {
    if PROTECTED_PATHS.iter().any(|p| path_matches(path, p)) {
        return false;
    }
    let parts: Vec<&str> = path.split('/').filter(|p| !p.is_empty() && *p != ".").collect();
    let directories = &parts[..parts.len().saturating_sub(1)];
    !directories.iter().any(|d| EXCLUDED_DIRECTORIES.contains(d)) && !GENERATED.is_match(path)
}

/// A number as Python keeps it: an int, or a float from a division.
#[derive(Clone, Copy)]
enum Num {
    Int(i64),
    Float(f64),
}

impl Num {
    fn value(self) -> f64 {
        match self {
            Num::Int(i) => i as f64,
            Num::Float(f) => f,
        }
    }

    fn json(self) -> Value {
        match self {
            Num::Int(i) => json!(i),
            Num::Float(f) => json!(f),
        }
    }
}

fn ratio(numerator: f64, denominator: usize) -> Num {
    if denominator == 0 {
        Num::Int(0)
    } else {
        Num::Float(numerator / denominator as f64)
    }
}

fn is_production_source(path: &str) -> bool {
    slop_language(path).is_some() && slop_included(path) && !is_test_path(path)
}

fn count_verbose_lines(
    production: &[(String, String)],
    covered: &BTreeMap<String, BTreeSet<i64>>,
) -> Result<usize, CheckError> {
    let mut verbose = 0usize;
    for (path, text) in production {
        let mut flagged = verbose_lines(path, text)?;
        flagged.extend(covered.get(path).into_iter().flatten().copied());
        verbose += flagged.len();
    }
    Ok(verbose)
}

fn slop_contributions(
    eroded_share: Num,
    eroded_count: usize,
    duplication: Num,
    clone_count: usize,
    cycle_density: Num,
    cycle_count: usize,
) -> (Map<String, Value>, i64) {
    let dimensions = [
        ("complexity-erosion", 0.5, eroded_share, 0.25, eroded_count, 20.0),
        ("duplication", 0.3, duplication, 0.15, clone_count, 15.0),
        ("import-cycle", 0.2, cycle_density, 0.10, cycle_count, 5.0),
    ];
    let mut contributions = Map::new();
    let mut total = 0.0;
    for (name, weight, density, saturation, count, scale) in dimensions {
        let points = (saturate(density.value(), saturation) + count_points(count as f64, scale)) / 2.0;
        let value = py::round(weight * points, 2);
        total += value;
        contributions.insert(name.into(), json!(value));
    }
    (contributions, ((total + 0.5) as i64).clamp(0, 100))
}

fn format_hotspots(eroded: &[&FunctionMetric]) -> Vec<Value> {
    let mut hotspots: Vec<&&FunctionMetric> = eroded.iter().collect();
    hotspots.sort_by(|a, b| b.mass().partial_cmp(&a.mass()).unwrap_or(std::cmp::Ordering::Equal));
    hotspots
        .iter()
        .map(|item| {
            json!({
                "path": item.path,
                "function": item.name,
                "lines": [item.start, item.end],
                "complexity": item.complexity,
                "sloc": item.sloc,
                "nesting": item.nesting,
                "mass": py::round(item.mass(), 1),
            })
        })
        .collect()
}

fn format_clone_groups(groups: &[Vec<Span>]) -> Vec<Value> {
    groups
        .iter()
        .map(|group| {
            Value::Array(
                group
                    .iter()
                    .map(|(p, s, e)| json!({"path": p, "lines": [s, e]}))
                    .collect(),
            )
        })
        .collect()
}

/// Raw structural metrics and the 0-100 sloppiness index (lower is better).
pub fn slop_measure(root: &Path, files: &[(String, String)], deadline: Deadline) -> Result<Value, CheckError> {
    let production: Vec<(String, String)> = files
        .iter()
        .filter(|(path, _)| is_production_source(path))
        .cloned()
        .collect();
    let python: Vec<&str> = production
        .iter()
        .filter(|(p, _)| slop_language(p) == Some("python"))
        .map(|(_, t)| t.as_str())
        .collect();
    pyast::prefetch(&python)?;
    pyast::prefetch_tokens(&python)?;
    let (exact, approximate) = exact_function_metrics(root, &production, deadline);
    let mut functions = Vec::new();
    for (path, text) in &production {
        functions.extend(function_metrics(path, text, exact.get(path))?);
    }
    let total_mass: f64 = functions.iter().map(FunctionMetric::mass).fold(0.0, |a, b| a + b);
    let eroded: Vec<&FunctionMetric> = functions.iter().filter(|f| f.complexity > SLOP_COMPLEXITY).collect();
    let lines: usize = production
        .iter()
        .map(|(_, text)| {
            py::splitlines(text, false)
                .iter()
                .filter(|l| !py::strip(l).is_empty())
                .count()
        })
        .sum();
    let (covered, groups) = clone_lines(&production, None)?;
    let cloned: usize = covered.values().map(BTreeSet::len).sum();
    let mut graph = python_import_graph(&production)?;
    graph.extend(javascript_import_graph(&production));
    graph.extend(elixir_import_graph(&production));
    let cycles = import_cycles(&graph);
    let verbose = count_verbose_lines(&production, &covered)?;
    let eroded_mass: f64 = eroded.iter().map(|f| f.mass()).fold(0.0, |a, b| a + b);
    let eroded_share = if total_mass != 0.0 {
        Num::Float(eroded_mass / total_mass)
    } else {
        Num::Int(0)
    };
    let duplication = ratio(cloned as f64, lines);
    let cycle_density = ratio(cycles.iter().map(Vec::len).sum::<usize>() as f64, graph.len());
    let verbosity = ratio(verbose as f64, lines);
    let languages: BTreeSet<&str> = production.iter().filter_map(|(p, _)| slop_language(p)).collect();
    let mut raw = Map::new();
    raw.insert("functions".into(), json!(functions.len()));
    raw.insert("eroded_functions".into(), json!(eroded.len()));
    raw.insert("eroded_share".into(), eroded_share.json());
    raw.insert("duplication_density".into(), duplication.json());
    raw.insert("clone_groups".into(), json!(groups.len()));
    raw.insert("cycle_density".into(), cycle_density.json());
    raw.insert("cycle_groups".into(), json!(cycles.len()));
    raw.insert("verbosity".into(), verbosity.json());
    raw.insert("lines".into(), json!(lines));
    raw.insert(
        "approximate_complexity".into(),
        json!(approximate.iter().collect::<Vec<_>>()),
    );
    raw.insert("languages".into(), json!(languages.iter().collect::<Vec<_>>()));
    let (contributions, index) = slop_contributions(
        eroded_share,
        eroded.len(),
        duplication,
        groups.len(),
        cycle_density,
        cycles.len(),
    );
    Ok(json!({
        "index": index,
        "contributions": contributions,
        "metrics": raw,
        "hotspots": format_hotspots(&eroded),
        "clone_groups": format_clone_groups(&groups),
        "import_cycles": cycles,
    }))
}

/// Path order as Python sorts `Path` objects: component by component.
fn path_order(a: &str, b: &str) -> std::cmp::Ordering {
    a.split('/').cmp(b.split('/'))
}

/// Tracked and non-ignored untracked sources; every source outside Git.
fn source_paths(root: &Path) -> Vec<String> {
    let skipped = |relative: &str| relative.split('/').any(|p| SKIP_DIRECTORIES.contains(&p));
    let mut paths: Vec<String> = match git_output(
        root,
        &["ls-files", "-z", "--cached", "--others", "--exclude-standard"],
        Deadline::none(),
        None,
    ) {
        Ok(listing) => listing
            .split(|&b| b == 0)
            .filter(|n| !n.is_empty())
            .map(|n| String::from_utf8_lossy(n).into_owned())
            .filter(|name| slop_language(name).is_some() && !skipped(name) && root.join(name).is_file())
            .collect(),
        Err(_) => {
            let mut found = Vec::new();
            walk(root, root, &mut found);
            found
                .into_iter()
                .filter(|relative| {
                    let name = relative.rsplit('/').next().unwrap_or(relative);
                    slop_language(name).is_some() && !skipped(relative)
                })
                .collect()
        }
    };
    paths.sort_by(|a, b| path_order(a, b));
    paths
}

/// Every file under `directory` (`rglob("*")` without following directory links).
fn walk(root: &Path, directory: &Path, found: &mut Vec<String>) {
    let Ok(entries) = std::fs::read_dir(directory) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(kind) = entry.file_type() else { continue };
        if kind.is_dir() {
            walk(root, &path, found);
        } else if path.is_file()
            && let Ok(relative) = path.strip_prefix(root)
        {
            found.push(relative.to_string_lossy().into_owned());
        }
    }
}

/// Readable source files by repository-relative path, within a byte budget.
pub fn repository_sources(root: &Path, limit: Option<u64>) -> Result<Vec<(String, String)>, CheckError> {
    let mut files = Vec::new();
    let mut total = 0u64;
    for relative in source_paths(root) {
        let path = root.join(&relative);
        let Ok(meta) = std::fs::metadata(&path) else { continue };
        if meta.len() > 1024 * 1024 {
            continue;
        }
        total += meta.len();
        if limit.is_some_and(|l| total > l) {
            return Err(CheckError::Value(
                "repository exceeds the write-time slop budget".into(),
            ));
        }
        if let Ok(text) = proc::read_text(&path) {
            files.push((relative, text));
        }
    }
    Ok(files)
}

fn base_sources(root: &Path, reference: &str) -> Result<Vec<(String, String)>, CheckError> {
    let directory = tempfile::Builder::new()
        .prefix("loki-slop-")
        .tempdir()
        .map_err(|e| CheckError::os(&e, None))?;
    let base = directory.path().join("base");
    let commit = git_output(
        root,
        &["rev-parse", "--verify", &format!("{reference}^{{commit}}")],
        Deadline::none(),
        None,
    )?;
    git::materialize_base(root, String::from_utf8_lossy(&commit).trim(), &base, Deadline::none())?;
    repository_sources(&base, None)
}

fn report_text(report: &Value, top: usize) -> String {
    let metrics = &report["metrics"];
    let contribution = |k: &str| report["contributions"][k].as_f64().unwrap_or(0.0);
    let number = |k: &str| metrics[k].as_f64().unwrap_or(0.0);
    let mut lines = vec![
        format!(
            "Sloppiness index: {}/100 (lower is better; trellis 0.2.0-provisional weights)",
            report["index"]
        ),
        format!(
            "  complexity-erosion {:5.1}  eroded share {:.2}, {} of {} functions with CC > {SLOP_COMPLEXITY}",
            contribution("complexity-erosion"),
            number("eroded_share"),
            metrics["eroded_functions"],
            metrics["functions"]
        ),
        format!(
            "  duplication        {:5.1}  density {:.2}, {} clone groups",
            contribution("duplication"),
            number("duplication_density"),
            metrics["clone_groups"]
        ),
        format!(
            "  import-cycle       {:5.1}  density {:.2}, {} cycles",
            contribution("import-cycle"),
            number("cycle_density"),
            metrics["cycle_groups"]
        ),
        format!(
            "Verbosity {:.2} over {} lines (reported, not scored)",
            number("verbosity"),
            metrics["lines"]
        ),
    ];
    let approximate: Vec<&str> = metrics["approximate_complexity"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect();
    if !approximate.is_empty() {
        lines.push(format!(
            "Complexity approximated structurally for: {}",
            approximate.join(", ")
        ));
    }
    let languages: Vec<&str> = metrics["languages"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect();
    if languages.contains(&"go") || languages.contains(&"rust") {
        lines.push(
            "Import cycles: not measured for Go (rejected by the compiler) or Rust (module cycles are legal)".into(),
        );
    }
    for item in report["hotspots"].as_array().into_iter().flatten().take(top) {
        lines.push(format!(
            "hotspot {}:{} {} CC {}, {} SLOC, mass {}",
            item["path"].as_str().unwrap_or(""),
            item["lines"][0],
            item["function"].as_str().unwrap_or(""),
            item["complexity"],
            item["sloc"],
            py::float_repr(item["mass"].as_f64().unwrap_or(0.0))
        ));
    }
    for group in report["clone_groups"].as_array().into_iter().flatten().take(top) {
        let members: Vec<String> = group
            .as_array()
            .into_iter()
            .flatten()
            .map(|m| {
                format!(
                    "{}:{}-{}",
                    m["path"].as_str().unwrap_or(""),
                    m["lines"][0],
                    m["lines"][1]
                )
            })
            .collect();
        lines.push(format!("clone {}", members.join(", ")));
    }
    for cycle in report["import_cycles"].as_array().into_iter().flatten().take(top) {
        let names: Vec<&str> = cycle
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect();
        lines.push(format!("import cycle {}", names.join(" -> ")));
    }
    lines.join("\n")
}

fn slop_policy_failures(policy: &Map<String, Value>, index: i64, previous: Option<&Value>) -> Vec<String> {
    let mut failures = Vec::new();
    if let Some(max) = policy.get("max_index").and_then(Value::as_i64)
        && index > max
    {
        failures.push(format!("index {index} exceeds max_index {max}"));
    }
    if let (Some(previous), Some(max)) = (previous, policy.get("max_index_increase").and_then(Value::as_i64)) {
        let increase = index - previous["index"].as_i64().unwrap_or(0);
        if increase > max {
            failures.push(format!("index rose by {increase}, above max_index_increase {max}"));
        }
    }
    failures
}

fn print_base_diff(base: &str, current: &Value, previous: &Value) {
    let index = current["index"].as_i64().unwrap_or(0);
    let before = previous["index"].as_i64().unwrap_or(0);
    println!("Base {base}: index {before} -> {index} ({:+})", index - before);
    let known: HashSet<(String, String)> = previous["hotspots"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|h| {
            (
                h["path"].as_str().unwrap_or("").to_string(),
                h["function"].as_str().unwrap_or("").to_string(),
            )
        })
        .collect();
    for item in current["hotspots"].as_array().into_iter().flatten() {
        let key = (
            item["path"].as_str().unwrap_or("").to_string(),
            item["function"].as_str().unwrap_or("").to_string(),
        );
        if !known.contains(&key) {
            println!("new hotspot {}:{} {}", key.0, item["lines"][0], key.1);
        }
    }
}

/// `loki slop`: print the report; exit 1 when the policy fails.
pub fn slop_command(
    root: &Path,
    config: &crate::config::Config,
    base: Option<&str>,
    as_json: bool,
    top: i64,
) -> Result<i32, CheckError> {
    crate::config::slop_block(config).map_err(CheckError::Value)?;
    let policy = config
        .get("slop")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let current = slop_measure(root, &repository_sources(root, None)?, Deadline::none())?;
    let previous = match base.filter(|b| !b.is_empty()) {
        Some(base) => Some(slop_measure(root, &base_sources(root, base)?, Deadline::none())?),
        None => None,
    };
    let index = current["index"].as_i64().unwrap_or(0);
    let failures = slop_policy_failures(&policy, index, previous.as_ref());
    if as_json {
        let document = json!({"current": current, "base": previous, "policy_failures": failures});
        println!("{}", py::dumps_indent(&document));
    } else {
        let top = usize::try_from(top).unwrap_or(0);
        println!("{}", report_text(&current, top));
        if let (Some(previous), Some(base)) = (&previous, base) {
            print_base_diff(base, &current, previous);
        }
        for failure in &failures {
            println!("loki slop: {failure}");
        }
    }
    Ok(i32::from(!failures.is_empty()))
}

fn match_changed_group(
    items: Vec<FunctionMetric>,
    rest: &[FunctionMetric],
) -> Vec<(FunctionMetric, Option<FunctionMetric>)> {
    let mut fallback: Option<&FunctionMetric> = None;
    for item in rest {
        if fallback.is_none_or(|f| item.complexity > f.complexity) {
            fallback = Some(item);
        }
    }
    let fallback = fallback.cloned();
    let count = items.len();
    items
        .into_iter()
        .enumerate()
        .map(|(index, item)| {
            let prior = if rest.len() == count {
                Some(rest[index].clone())
            } else {
                fallback.clone()
            };
            (item, prior)
        })
        .collect()
}

/// Functions an edit added or changed, each with its committed counterpart.
fn changed_functions(
    old: Vec<FunctionMetric>,
    new: Vec<FunctionMetric>,
    before: &str,
    after: &str,
) -> Vec<(FunctionMetric, Option<FunctionMetric>)> {
    let source = |lines: &[&str], item: &FunctionMetric| -> String {
        lines[py_range(lines.len(), item.start - 1, item.end)]
            .iter()
            .map(|l| py::strip(l))
            .collect::<Vec<_>>()
            .join("\n")
    };
    let (old_lines, new_lines) = (py::splitlines(before, false), py::splitlines(after, false));
    let mut committed: Vec<(String, Vec<(String, FunctionMetric)>)> = Vec::new();
    for item in old {
        let text = source(&old_lines, &item);
        match committed.iter_mut().find(|(n, _)| *n == item.name) {
            Some((_, list)) => list.push((text, item)),
            None => committed.push((item.name.clone(), vec![(text, item)])),
        }
    }
    let mut changed: Vec<(String, Vec<FunctionMetric>)> = Vec::new();
    for item in new {
        let text = source(&new_lines, &item);
        let namesakes = committed.iter_mut().find(|(n, _)| *n == item.name).map(|(_, l)| l);
        let same = namesakes
            .as_ref()
            .and_then(|list| list.iter().position(|(t, _)| *t == text));
        match (same, namesakes) {
            (Some(position), Some(list)) => {
                list.remove(position);
            }
            _ => match changed.iter_mut().find(|(n, _)| *n == item.name) {
                Some((_, list)) => list.push(item),
                None => changed.push((item.name.clone(), vec![item])),
            },
        }
    }
    let mut pairs = Vec::new();
    for (name, items) in changed {
        let rest: Vec<FunctionMetric> = committed
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, l)| l.iter().map(|(_, i)| i.clone()).collect())
            .unwrap_or_default();
        pairs.extend(match_changed_group(items, &rest));
    }
    pairs.sort_by_key(|(item, _)| item.start);
    pairs
}

type TextPairMap = (HashMap<String, String>, HashMap<String, String>);

fn load_written_texts(root: &Path, names: &[String], deadline: Deadline) -> Result<TextPairMap, CheckError> {
    let mut after = HashMap::new();
    let mut before = HashMap::new();
    for name in names {
        after.insert(
            name.clone(),
            proc::read_text(&root.join(name)).map_err(CheckError::Value)?,
        );
    }
    for name in names {
        before.insert(name.clone(), head_text(root, name, deadline)?);
    }
    Ok((before, after))
}

fn written_complexity_notes(
    root: &Path,
    names: &[String],
    before: &HashMap<String, String>,
    after: &HashMap<String, String>,
    deadline: Deadline,
) -> Result<Vec<String>, CheckError> {
    let cheap: Vec<(String, String)> = names
        .iter()
        .filter(|n| matches!(slop_language(n), Some("typescript" | "go")))
        .flat_map(|n| {
            [
                (format!("after/{n}"), after[n].clone()),
                (format!("before/{n}"), before[n].clone()),
            ]
        })
        .filter(|(_, text)| !text.is_empty())
        .collect();
    let (exact, _) = exact_function_metrics(root, &cheap, deadline);
    let side = |prefix: &str, name: &str| exact.get(&format!("{prefix}{name}"));
    let python: Vec<&str> = names
        .iter()
        .filter(|n| slop_language(n) == Some("python"))
        .flat_map(|n| [after[n].as_str(), before[n].as_str()])
        .collect();
    pyast::prefetch(&python)?;
    let mut notes = Vec::new();
    for name in names {
        let old = function_metrics(name, &before[name], side("before/", name))?;
        let new = function_metrics(name, &after[name], side("after/", name))?;
        for (item, prior) in changed_functions(old, new, &before[name], &after[name]) {
            if item.complexity > SLOP_COMPLEXITY && prior.as_ref().is_none_or(|p| item.complexity > p.complexity) {
                let change = prior
                    .as_ref()
                    .map_or(String::new(), |p| format!("{} -> ", p.complexity));
                notes.push(format!(
                    "{name}:{}: loki/slop-complexity: {} cyclomatic complexity {change}{} (> {SLOP_COMPLEXITY}); split it into smaller functions",
                    item.start, item.name, item.complexity
                ));
            }
        }
    }
    Ok(notes)
}

fn merge_before_sources(
    repository: &[(String, String)],
    names: &[String],
    before: &HashMap<String, String>,
) -> Vec<(String, String)> {
    let mut merged = repository.to_vec();
    for name in names {
        match merged.iter_mut().find(|(p, _)| p == name) {
            Some(entry) => entry.1 = before[name].clone(),
            None => merged.push((name.clone(), before[name].clone())),
        }
    }
    merged
}

fn written_clone_notes(
    repository: &[(String, String)],
    merged: &[(String, String)],
    focus: &HashSet<String>,
) -> Result<Vec<String>, CheckError> {
    let (_, groups_after) = clone_lines(repository, Some(focus))?;
    let (_, groups_before) = clone_lines(merged, Some(focus))?;
    let mut notes = Vec::new();
    if groups_after.len() <= groups_before.len() {
        return Ok(notes);
    }
    let seen: HashSet<Vec<String>> = groups_before
        .iter()
        .map(|g| {
            let mut paths: Vec<String> = g.iter().map(|(p, _, _)| p.clone()).collect();
            paths.sort();
            paths
        })
        .collect();
    for group in &groups_after {
        let mut paths: Vec<String> = group.iter().map(|(p, _, _)| p.clone()).collect();
        paths.sort();
        if seen.contains(&paths) {
            continue;
        }
        let here = group.iter().find(|m| focus.contains(&m.0)).unwrap_or(&group[0]);
        let others: Vec<String> = group
            .iter()
            .filter(|m| *m != here)
            .map(|(p, s, e)| format!("{p}:{s}-{e}"))
            .collect();
        notes.push(format!(
            "{}:{}: loki/slop-duplication: lines {}-{} duplicate {}; reuse or extract the shared code",
            here.0,
            here.1,
            here.1,
            here.2,
            others.join(", ")
        ));
    }
    Ok(notes)
}

fn written_cycle_notes(
    repository: &[(String, String)],
    merged: &[(String, String)],
    focus: &HashSet<String>,
) -> Result<Vec<String>, CheckError> {
    let mut graphs = Vec::new();
    for sources in [merged, repository] {
        let mut graph = python_import_graph(sources)?;
        graph.extend(javascript_import_graph(sources));
        graphs.push(graph);
    }
    let old_cycles: HashSet<Vec<String>> = import_cycles(&graphs[0]).into_iter().collect();
    let mut notes = Vec::new();
    for cycle in import_cycles(&graphs[1]) {
        if old_cycles.contains(&cycle) {
            continue;
        }
        if let Some(member) = cycle.iter().find(|m| focus.contains(*m)) {
            notes.push(format!(
                "{member}: loki/slop-import-cycle: import cycle {}",
                cycle.join(" -> ")
            ));
        }
    }
    Ok(notes)
}

/// Hotspots, clones and cycles an edit introduces, against committed text.
pub fn written_slop(root: &Path, targets: &[PathBuf], deadline: Deadline) -> Result<Vec<String>, CheckError> {
    let root = resolve(root);
    let names: Vec<String> = targets
        .iter()
        .filter(|p| p.is_file() && slop_language(&p.to_string_lossy()).is_some())
        .filter_map(|p| p.strip_prefix(&root).ok().map(|r| r.to_string_lossy().into_owned()))
        .collect();
    if names.is_empty() {
        return Ok(vec![]);
    }
    let (before, after) = load_written_texts(&root, &names, deadline)?;
    let mut notes = written_complexity_notes(&root, &names, &before, &after, deadline)?;
    let repository = match repository_sources(&root, Some(SLOP_WRITE_BUDGET)) {
        Ok(files) => files,
        Err(CheckError::Value(_)) => return Ok(notes),
        Err(other) => return Err(other),
    };
    let focus: HashSet<String> = names.iter().cloned().collect();
    let merged = merge_before_sources(&repository, &names, &before);
    notes.extend(written_clone_notes(&repository, &merged, &focus)?);
    notes.extend(written_cycle_notes(&repository, &merged, &focus)?);
    notes.truncate(MAX_VIOLATIONS);
    Ok(notes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loki_slop_normpath_matches_python() {
        // python3 -c 'import os; print([os.path.normpath(p) for p in ["./b", "a/../../c", "a/./b//c", "a/.."]])'
        let got: Vec<String> = ["./b", "a/../../c", "a/./b//c", "a/.."]
            .iter()
            .map(|p| normpath(p))
            .collect();
        assert_eq!(got, ["b", "../c", "a/b/c", "."]);
    }

    #[test]
    fn loki_slop_path_order_is_component_wise() {
        // python3 -c 'from pathlib import Path; print(sorted([Path("a.py"), Path("a/b.py"), Path("a-b.py")]))'
        let mut paths = vec!["a.py", "a/b.py", "a-b.py"];
        paths.sort_by(|a, b| path_order(a, b));
        assert_eq!(paths, ["a/b.py", "a-b.py", "a.py"]);
    }
}
