import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { isAbsolute, resolve } from "node:path";
import { fileURLToPath } from "node:url";

type Handler = (event: unknown, ctx?: { cwd?: string }) => unknown | Promise<unknown>;
export type ExtensionApi = {
  on: (event: string, handler: Handler) => void;
  sendMessage?: (message: { content: Array<{ text: string; type: "text" }>; customType: string }, options: { triggerTurn: boolean }) => void;
};

function checkerArgs(root: string): string[] {
  return [`${root}/.loki/loki.py`, "--root", root];
}

const NOT_ON_BRANCH = "loki: .loki/loki.py is not on this branch; Loki did not check this";

/** A checkout whose working tree and HEAD lack the engine while another ref has it: a branch without Loki. */
export function branchWithoutLoki(root: string): boolean {
  if (existsSync(checkerArgs(root)[0])) return false;
  const git = (args: string[]) => spawnSync("git", ["-C", root, ...args], { encoding: "utf8", timeout: 5_000 });
  if (git(["cat-file", "-e", "HEAD:.loki/loki.py"]).status === 0) return false;
  const other = git(["rev-list", "-1", "--all", "--", ".loki/loki.py"]);
  return other.status === 0 && other.stdout.trim() !== "";
}

type CheckOutcome = { failed: boolean; text: string };

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object";
}

function notifyLoki(api: ExtensionApi, text: string) {
  try {
    api.sendMessage?.({ customType: "loki", content: [{ type: "text", text }] }, { triggerTurn: false });
  } catch {
    /* Notifications must not block or discard results. */
  }
}

let branchNoted = false;
function skipOffBranch(api: ExtensionApi, root: string): boolean {
  if (!branchWithoutLoki(root)) return false;
  if (!branchNoted) {
    branchNoted = true;
    notifyLoki(api, NOT_ON_BRANCH);
  }
  return true;
}

function parseContextOutput(stdout: string): string {
  const output: unknown = JSON.parse(stdout);
  if (!isRecord(output) || !("hookSpecificOutput" in output)) throw new Error("loki: invalid context output");
  const specific = output.hookSpecificOutput;
  if (!isRecord(specific) || typeof specific.additionalContext !== "string" || !specific.additionalContext) {
    throw new Error("loki: empty context output");
  }
  return specific.additionalContext;
}

function contextText(root: string): string {
  const result = spawnSync("python3", [...checkerArgs(root), "context", "--event", "SessionStart"], { cwd: root, encoding: "utf8", timeout: 5_000 });
  if (result.error || result.signal || result.status !== 0) {
    throw result.error ?? new Error(result.stderr?.trim() || "loki: context unavailable");
  }
  return parseContextOutput(result.stdout);
}

export function installContext(api: ExtensionApi, root: string) {
  api.on("before_agent_start", async (value) => {
    if (!isRecord(value) || !("systemPrompt" in value)) return;
    const current = value.systemPrompt;
    if (typeof current !== "string" && !(Array.isArray(current) && current.every(part => typeof part === "string"))) return;
    let text: string;
    try {
      text = contextText(root);
    } catch {
      text = "LOKI context unavailable; follow hook diagnostics.";
    }
    return { systemPrompt: Array.isArray(current) ? [...current, text] : `${current}${current ? "\n\n" : ""}${text}` };
  });
}

function resolveFileUri(value: string): string {
  const scheme = /^([a-z][a-z0-9+.-]*):\/\//i.exec(value);
  if (!scheme) return value;
  if (scheme[1].toLowerCase() !== "file") throw new Error(`loki: unsupported target URI: ${scheme[1]}`);
  const url = new URL(value);
  if (url.hostname && url.hostname !== "localhost") throw new Error("loki: unsupported target URI: file");
  return fileURLToPath(url);
}

export function localTarget(value: unknown, cwd: string): string {
  if (typeof value !== "string" || !value || value.includes("\0")) throw new Error("loki: invalid target path");
  if (typeof cwd !== "string" || !isAbsolute(cwd) || cwd.includes("\0")) throw new Error("loki: invalid handler cwd");
  return resolve(cwd, resolveFileUri(value));
}

export function directPaths(_toolName: string, input: unknown, cwd: string): string[] {
  if (!isRecord(input) || !("path" in input)) throw new Error("loki: invalid matched write input");
  return [localTarget(input.path, cwd)];
}

function errorMessage(error: unknown): string {
  const message = error instanceof Error ? error.message : String(error);
  return message || "loki: checker unavailable";
}

function formatCheckerResult(result: ReturnType<typeof spawnSync>): CheckOutcome {
  const failed = Boolean(result.error || result.signal || result.status !== 0);
  const stderr = typeof result.stderr === "string" ? result.stderr.trim() : "";
  if (stderr) return { failed, text: stderr };
  if (!failed) return { failed: false, text: "" };
  const detail = result.error?.message || result.signal || `exit status ${result.status}`;
  return { failed: true, text: `loki: checker unavailable: ${detail}` };
}

function runChecker(root: string, args: string[], timeout: number, input?: string): CheckOutcome {
  const options = input === undefined
    ? { cwd: root, encoding: "utf8" as const, timeout }
    : { cwd: root, encoding: "utf8" as const, timeout, input };
  return formatCheckerResult(spawnSync("python3", [...checkerArgs(root), ...args], options));
}

function isWriteToolEvent(value: unknown, phase: string): value is Record<string, unknown> & { toolName: "edit" | "write" } {
  if (!isRecord(value)) return false;
  if (value.toolName !== "edit" && value.toolName !== "write") return false;
  return !(phase === "tool_result" && value.isError === true);
}

function runGuardCheck(
  root: string,
  phase: string,
  value: Record<string, unknown> & { toolName: "edit" | "write" },
  cwd: unknown,
  extract: (toolName: string, input: unknown, cwd: string) => string[],
  previewHost: "pi" | "omp",
): CheckOutcome {
  try {
    if (typeof cwd !== "string") throw new Error("loki: missing handler cwd");
    const paths = extract(value.toolName, value.input, cwd);
    if (!paths.length) throw new Error("loki: no matched write targets");
    const targets = [...new Set(paths.map(path => localTarget(path, cwd)))];
    const preview = phase === "tool_call";
    const args = [preview ? "protect" : "hook", ...targets.flatMap(path => ["--file", path]), ...(preview ? ["--preview", previewHost] : [])];
    const input = preview ? JSON.stringify({ cwd, tool_name: value.toolName, tool_input: value.input }) : undefined;
    return runChecker(root, args, 30_000, input);
  } catch (error) {
    return { failed: true, text: errorMessage(error) };
  }
}

function handleToolCallOutcome(api: ExtensionApi, { failed, text }: CheckOutcome) {
  if (!failed && text) notifyLoki(api, text);
  return failed ? { block: true, reason: text } : undefined;
}

function handleToolResultOutcome(api: ExtensionApi, value: Record<string, unknown>, { failed, text }: CheckOutcome) {
  if (!failed && !text) return;
  const content = Array.isArray(value.content) ? value.content : [];
  const diagnostic = failed ? `loki gate failed:\n${text}` : text;
  notifyLoki(api, diagnostic);
  return { content: [...content, { type: "text", text: diagnostic }], ...(failed ? { isError: true } : {}) };
}

export function installGuard(api: ExtensionApi, root: string, extract: (toolName: string, input: unknown, cwd: string) => string[], previewHost: "pi" | "omp" = "pi") {
  for (const phase of ["tool_call", "tool_result"]) {
    api.on(phase, async (value, ctx) => {
      if (!isWriteToolEvent(value, phase) || skipOffBranch(api, root)) return;
      const outcome = runGuardCheck(root, phase, value, ctx?.cwd, extract, previewHost);
      return phase === "tool_call" ? handleToolCallOutcome(api, outcome) : handleToolResultOutcome(api, value, outcome);
    });
  }
}

function eventCwd(value: Record<string, unknown>, ctx?: { cwd?: string }): string | undefined {
  return typeof value.cwd === "string" ? value.cwd : ctx?.cwd;
}

function runUltronBeforeWrite(root: string, value: Record<string, unknown>, ctx?: { cwd?: string }): CheckOutcome {
  try {
    const cwd = eventCwd(value, ctx);
    if (typeof cwd !== "string") throw new Error("loki: missing handler cwd");
    if (typeof value.content !== "string") throw new Error("loki: invalid write content");
    const path = localTarget(value.path, cwd);
    const input = JSON.stringify({ cwd, tool_name: "write", tool_input: { path, content: value.content } });
    return runChecker(root, ["protect", "--file", path, "--preview", "ultron"], 30_000, input);
  } catch (error) {
    return { failed: true, text: errorMessage(error) };
  }
}

function handleUltronBeforeWrite(api: ExtensionApi, root: string, value: unknown, ctx?: { cwd?: string }) {
  if (!isRecord(value) || !("path" in value) || !("content" in value)) return;
  if (skipOffBranch(api, root)) return;
  const { failed, text } = runUltronBeforeWrite(root, value, ctx);
  if (failed) return { block: true, reason: text };
  return text ? { message: text } : undefined;
}

function collectCellTargets(value: Record<string, unknown>, cwd: string): string[] {
  const files = Array.isArray(value.files) ? value.files : [];
  const checked = Array.isArray(value.checked) ? value.checked : [];
  return [...new Set([...files, ...checked].filter((path): path is string => typeof path === "string").map(path => localTarget(path, cwd)))];
}

function handleUltronAfterCell(api: ExtensionApi, root: string, value: unknown, ctx?: { cwd?: string }) {
  if (!isRecord(value) || !Array.isArray(value.files)) return;
  const cwd = eventCwd(value, ctx);
  if (typeof cwd !== "string") return;
  const targets = collectCellTargets(value, cwd);
  if (!targets.length || skipOffBranch(api, root)) return;
  const { failed, text } = runChecker(root, ["hook", ...targets.flatMap(path => ["--file", path])], 60_000);
  return text ? { message: failed ? `loki gate failed:\n${text}` : text } : undefined;
}

/**
 * Ultron's REPL writes files from Python, so Pi's edit/write tool events never fire there. Ultron instead emits
 * `before_file_write` ({path, content}) before `edit()`/`write()` change a file, and `after_cell_changes`
 * ({files, checked}) with the files a cell changed by other means. Ultron's built-in Loki integration handles both
 * itself and sets ULTRON_LOKI_BUILTIN=1; this extension then stays out of the way instead of checking twice.
 */
export function installUltron(api: ExtensionApi, root: string, env: NodeJS.ProcessEnv = process.env) {
  if (env.ULTRON_LOKI_BUILTIN === "1") return;
  api.on("before_file_write", async (value, ctx) => handleUltronBeforeWrite(api, root, value, ctx));
  api.on("after_cell_changes", async (value, ctx) => handleUltronAfterCell(api, root, value, ctx));
}

export default function (api: ExtensionApi) {
  const root = fileURLToPath(new URL("../../", import.meta.url));
  installContext(api, root);
  installGuard(api, root, directPaths);
  installUltron(api, root);
}
