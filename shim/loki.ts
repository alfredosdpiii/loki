import { spawnSync } from "node:child_process";
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

function contextText(root: string): string {
  const result = spawnSync("python3", [...checkerArgs(root), "context", "--event", "SessionStart"], { cwd: root, encoding: "utf8", timeout: 5_000 });
  if (result.error || result.signal || result.status !== 0) throw result.error ?? new Error(result.stderr?.trim() || "loki: context unavailable");
  const output: unknown = JSON.parse(result.stdout);
  if (!output || typeof output !== "object" || !("hookSpecificOutput" in output)) throw new Error("loki: invalid context output");
  const specific = output.hookSpecificOutput;
  if (!specific || typeof specific !== "object" || !("additionalContext" in specific) || typeof specific.additionalContext !== "string" || !specific.additionalContext) throw new Error("loki: empty context output");
  return specific.additionalContext;
}

export function installContext(api: ExtensionApi, root: string) {
  api.on("before_agent_start", async (value) => {
    if (!value || typeof value !== "object" || !("systemPrompt" in value)) return;
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

export function localTarget(value: unknown, cwd: string): string {
  if (typeof value !== "string" || !value || value.includes("\0")) throw new Error("loki: invalid target path");
  if (typeof cwd !== "string" || !isAbsolute(cwd) || cwd.includes("\0")) throw new Error("loki: invalid handler cwd");
  const scheme = /^([a-z][a-z0-9+.-]*):\/\//i.exec(value);
  if (scheme) {
    if (scheme[1].toLowerCase() !== "file") throw new Error(`loki: unsupported target URI: ${scheme[1]}`);
    const url = new URL(value);
    if (url.hostname && url.hostname !== "localhost") throw new Error("loki: unsupported target URI: file");
    value = fileURLToPath(url);
  }
  return resolve(cwd, value as string);
}

export function directPaths(_toolName: string, input: unknown, cwd: string): string[] {
  if (!input || typeof input !== "object" || !("path" in input)) throw new Error("loki: invalid matched write input");
  return [localTarget(input.path, cwd)];
}

export function installGuard(api: ExtensionApi, root: string, extract: (toolName: string, input: unknown, cwd: string) => string[], previewHost: "pi" | "omp" = "pi") {
  for (const phase of ["tool_call", "tool_result"]) {
    api.on(phase, async (value, ctx) => {
      if (!value || typeof value !== "object" || !("toolName" in value) || (value.toolName !== "edit" && value.toolName !== "write")) return;
      if (phase === "tool_result" && "isError" in value && value.isError === true) return;
      let failed = true;
      let text: string;
      try {
        const cwd = ctx?.cwd;
        if (typeof cwd !== "string") throw new Error("loki: missing handler cwd");
        const paths = extract(value.toolName, "input" in value ? value.input : undefined, cwd);
        if (!paths.length) throw new Error("loki: no matched write targets");
        const targets = [...new Set(paths.map(path => localTarget(path, cwd)))];
        const preview = phase === "tool_call";
        const result = spawnSync("python3", [...checkerArgs(root), preview ? "protect" : "hook", ...targets.flatMap(path => ["--file", path]), ...(preview ? ["--preview", previewHost] : [])], {
          cwd: root, encoding: "utf8", timeout: 30_000,
          ...(preview ? { input: JSON.stringify({ cwd, tool_name: value.toolName, tool_input: "input" in value ? value.input : undefined }) } : {}),
        });
        failed = Boolean(result.error || result.signal || result.status !== 0);
        text = result.stderr?.trim() || (failed ? `loki: checker unavailable: ${result.error?.message || result.signal || `exit status ${result.status}`}` : "");
      } catch (error) {
        text = error instanceof Error ? error.message : String(error);
        if (!text) text = "loki: checker unavailable";
      }
      if (phase === "tool_call") {
        if (!failed && text) {
          try { api.sendMessage?.({ customType: "loki", content: [{ type: "text", text }] }, { triggerTurn: false }); } catch { /* Admission must not depend on notifications. */ }
        }
        return failed ? { block: true, reason: text } : undefined;
      }
      if (!failed && !text) return;
      const content = "content" in value && Array.isArray(value.content) ? value.content : [];
      const diagnostic = failed ? `loki gate failed:\n${text}` : text;
      try { api.sendMessage?.({ customType: "loki", content: [{ type: "text", text: diagnostic }] }, { triggerTurn: false }); } catch { /* Notification must not discard the tool result. */ }
      return { content: [...content, { type: "text", text: diagnostic }], ...(failed ? { isError: true } : {}) };
    });
  }
}

export default function (api: ExtensionApi) {
  const root = fileURLToPath(new URL("../../", import.meta.url));
  installContext(api, root);
  installGuard(api, root, directPaths);
}
