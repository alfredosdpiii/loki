import { expect, test } from "bun:test";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, copyFileSync, readFileSync, existsSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import { installContext, installGuard, directPaths, type ExtensionApi } from "../shim/loki.ts";

type Handler = Parameters<ExtensionApi["on"]>[1];
function fixture(checker?: string) {
  const root = mkdtempSync(join(tmpdir(), "loki-shim-test-"));
  mkdirSync(join(root, ".loki"));
  if (checker !== undefined) writeFileSync(join(root, ".loki/loki.py"), checker);
  const handlers: Record<string, Handler> = {};
  const messages: unknown[] = [];
  const api: ExtensionApi = {
    on: (name, handler) => { handlers[name] = handler; },
    sendMessage: (message) => { messages.push(message); },
  };
  installContext(api, root);
  installGuard(api, root, directPaths);
  return { root, handlers, messages, cleanup: () => rmSync(root, { recursive: true, force: true }) };
}

test("Pi context uses real Python and preserves existing system prompt", async () => {
  const f = fixture();
  try {
    copyFileSync(fileURLToPath(new URL("../loki.py", import.meta.url)), join(f.root, ".loki/loki.py"));
    writeFileSync(join(f.root, ".loki/loki.json"), '{"rule_packs":["core"]}');
    const result = await f.handlers.before_agent_start({ systemPrompt: "Existing system" });
    expect(result).toHaveProperty("systemPrompt");
    expect((result as { systemPrompt: string }).systemPrompt).toStartWith("Existing system\n\nLOKI POLICY GUIDANCE");
    expect((result as { systemPrompt: string }).systemPrompt).not.toContain("Python edits");
  } finally { f.cleanup(); }
});

(process.env.LOKI_TEST_OXLINT ? test : test.skip)("installed Pi and OMP block proposed content using the real analyzer", async () => {
  const parent = mkdtempSync(join(tmpdir(), "loki-content-adapters-"));
  const root = join(parent, "repo");
  try {
    const source = fileURLToPath(new URL("../loki.py", import.meta.url));
    expect(spawnSync("python3", [source, "init", "--dir", root, "--managed-dir", join(parent, "engines")], { encoding: "utf8" }).status).toBe(0);
    mkdirSync(join(root, "node_modules/.bin"), { recursive: true });
    symlinkSync(process.env.LOKI_TEST_OXLINT!, join(root, "node_modules/.bin/oxlint"));
    const path = join(root, "source.test.ts");
    writeFileSync(path, "export const value = 1;\n");
    for (const host of ["pi", "omp"]) {
      const handlers: Record<string, Handler[]> = {};
      const extension = await import(join(root, `.${host}/extensions/loki.ts`));
      await extension.default({
        on: (name: string, handler: Handler) => { (handlers[name] ??= []).push(handler); },
      });
      for (const [content, blocked] of [
        ["try { run(); } catch {}", true],
        ['import {test} from "vitest"; test.skip("value",()=>{});', true],
        ['const message = "test.skip() and catch {}";', false],
        ["try { run(); } catch (error) { throw error; }", false],
      ] as const) {
        const results = await Promise.all(handlers.tool_call.map(handler =>
          handler({ toolName: "write", input: { path, content } }, { cwd: root })));
        expect(results.some(result => (result as { block?: boolean } | undefined)?.block)).toBe(blocked);
        expect(readFileSync(path, "utf8")).toBe("export const value = 1;\n");
      }
    }
  } finally { rmSync(parent, { recursive: true, force: true }); }
});

test("real checker failures block pre-write and preserve post-write result content", async () => {
  for (const checker of [
    undefined,
    "raise RuntimeError('fixture crash')\n",
    "import sys\nsys.exit(2)\n",
    "import os, signal\nos.kill(os.getpid(), signal.SIGTERM)\n",
  ]) {
    const f = fixture(checker);
    try {
      const event = { toolName: "write", input: { path: "a.txt" }, content: [{ type: "text", text: "original result" }] };
      const ctx = { cwd: f.root };
      const pre = await f.handlers.tool_call(event, ctx);
      expect(pre).toHaveProperty("block", true);
      expect((pre as { reason: string }).reason.length).toBeGreaterThan(0);
      const post = await f.handlers.tool_result(event, ctx);
      expect(post).toHaveProperty("isError", true);
      expect((post as { content: unknown[] }).content[0]).toEqual(event.content[0]);
      expect(f.messages.length).toBe(1);
      const context = await f.handlers.before_agent_start({ systemPrompt: "" });
      expect((context as { systemPrompt: string }).systemPrompt).toContain("context unavailable");
    } finally { f.cleanup(); }
  }
});

test("warnings reach tool results without pretending to deny the write", async () => {
  const f = fixture("import sys\nprint('NOT BLOCKED WARN Sobelow medium', file=sys.stderr)\n");
  try {
    const event = { toolName: "write", input: { path: "a.txt" }, content: [] };
    expect(await f.handlers.tool_call(event, { cwd: f.root })).toBeUndefined();
    expect(f.messages.length).toBe(1);
    const post = await f.handlers.tool_result(event, { cwd: f.root });
    expect(post).not.toHaveProperty("isError");
    expect((post as { content: { text: string }[] }).content[0].text).toContain("Sobelow medium");
    expect(f.messages.length).toBe(2);
    expect(await f.handlers.tool_result({ ...event, isError: true }, { cwd: f.root })).toBeUndefined();
    expect(await f.handlers.tool_call(event)).toHaveProperty("block", true);
  } finally { f.cleanup(); }
});

test("malformed context JSON degrades visibly without removing system instructions", async () => {
  for (const output of ["not JSON", "{}", '{"hookSpecificOutput":{"additionalContext":""}}']) {
    const f = fixture(`print(${JSON.stringify(output)})\n`);
    try {
      const result = await f.handlers.before_agent_start({ systemPrompt: "Keep me" });
      expect((result as { systemPrompt: string }).systemPrompt).toBe("Keep me\n\nLOKI context unavailable; follow hook diagnostics.");
    } finally { f.cleanup(); }
  }
});

test("OMP prompt arrays retain every original segment on success and failure", async () => {
  for (const checker of [
    'print(\'{"hookSpecificOutput":{"additionalContext":"policy"}}\')\n',
    "raise RuntimeError('fixture failure')\n",
  ]) {
    const f = fixture(checker);
    try {
      const original = ["base instructions", "workspace instructions"];
      const result = await f.handlers.before_agent_start({ systemPrompt: original });
      const prompt = (result as { systemPrompt: string[] }).systemPrompt;
      expect(prompt.slice(0, 2)).toEqual(original);
      expect(prompt.length).toBe(3);
      expect(original.length).toBe(2);
      expect(await f.handlers.before_agent_start({ systemPrompt: 42 })).toBeUndefined();
      expect(await f.handlers.before_agent_start({})).toBeUndefined();
    } finally { f.cleanup(); }
  }
});

test("installed Pi and OMP use relocated engine for context, files and shell permissions", async () => {
  const parent = mkdtempSync(join(tmpdir(), "loki-managed-adapters-"));
  const root = join(parent, "repo with spaces");
  try {
    const source = fileURLToPath(new URL("../loki.py", import.meta.url));
    const installed = spawnSync("python3", [
      source, "init", "--dir", root, "--managed-dir", join(parent, "engines"), "--shell-guard",
    ], { encoding: "utf8" });
    expect(installed.status).toBe(0);
    const config = JSON.parse(readFileSync(join(root, ".loki/loki.json"), "utf8"));
    config.shell_commands = [{ command: "npm test", cwd: ".", inputs: ["package.json"] }];
    writeFileSync(join(root, ".loki/loki.json"), JSON.stringify(config));
    const packageJson = '{"scripts":{"test":"touch canary"}}';
    writeFileSync(join(root, "package.json"), packageJson);
    for (const args of [["init"], ["add", "."], ["commit", "-m", "Reviewed fixture shell permission"]]) {
      const result = spawnSync("git", args, { cwd: root, encoding: "utf8" });
      expect(result.status).toBe(0);
    }
    writeFileSync(join(root, ".loki/loki.py"), "raise RuntimeError('candidate engine replaced')\n");
    for (const host of ["pi", "omp"]) {
      const handlers: Record<string, Handler[]> = {};
      const extension = await import(join(root, `.${host}/extensions/loki.ts`));
      await extension.default({
        on: (name: string, handler: Handler) => { (handlers[name] ??= []).push(handler); },
      });
      const context = await handlers.before_agent_start[0]({ systemPrompt: "Host prompt" });
      expect((context as { systemPrompt: string }).systemPrompt).toContain("LOKI POLICY GUIDANCE");
      expect((context as { systemPrompt: string }).systemPrompt).toStartWith("Host prompt\n\n");
      const results = await Promise.all(handlers.tool_call.map(handler => handler({
        toolName: "write", input: { path: ".loki/loki.json" },
      }, { cwd: root })));
      expect(results.some(result => (result as { block?: boolean } | undefined)?.block)).toBe(true);
      const allowed = await Promise.all(handlers.tool_call.map(handler => handler({
        toolName: "write", input: { path: "ordinary.txt" },
      }, { cwd: root })));
      expect(allowed.every(result => result === undefined)).toBe(true);
      const shell = (command: string) => Promise.all(handlers.tool_call.map(handler =>
        handler({ toolName: "bash", input: { command } }, { cwd: root })));
      expect((await shell("npm test")).every(result => result === undefined)).toBe(true);
      expect(existsSync(join(root, "canary"))).toBe(false);
      expect((await shell("printf x > notes.txt")).every(result => result === undefined))
        .toBe(true);
      for (const command of ["npm test -- --update", "git reset --hard", "printf x > notes.ts"]) {
        expect((await shell(command)).some(result =>
          (result as { block?: boolean } | undefined)?.block)).toBe(true);
      }
      writeFileSync(join(root, "package.json"), "{}");
      expect((await shell("npm test")).some(result =>
        (result as { block?: boolean } | undefined)?.block)).toBe(true);
      writeFileSync(join(root, "package.json"), packageJson);
    }
  } finally { rmSync(parent, { recursive: true, force: true }); }
});
