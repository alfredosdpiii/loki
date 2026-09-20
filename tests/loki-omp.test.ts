import { expect, mock, test } from "bun:test";

let inspection: unknown = { paths: ["a.txt", ".loki/loki.json"], fileOps: [] };
mock.module("@oh-my-pi/pi-natives", () => ({ editInspect: () => { if (inspection instanceof Error) throw inspection; return inspection; } }));
// Exercise module loading with the native boundary substituted; real runtime is verified separately.
const { default: install } = await import("../shim/loki-omp.ts");

test("OMP rejects unsafe target interpretations and unavailable inspection", async () => {
  const handlers: Record<string, Function> = {};
  await install({ on: (name, handler) => { handlers[name] = handler; } });
  const ctx = { cwd: "/tmp" };
  for (const path of ["ssh://host/a", "xd://tool", "a.db:rows", "a.zip:member", "a.py:3"] ) {
    inspection = { paths: [path], fileOps: [] };
    const result = await handlers.tool_call({ toolName: "edit", input: { input: "opaque native input" } }, ctx);
    expect(result.block).toBe(true);
    expect(result.reason).toContain("unsupported target");
  }
  inspection = new Error("native unavailable");
  const result = await handlers.tool_call({ toolName: "edit", input: { path: "a.txt" } }, ctx);
  expect(result.reason).toContain("OMP edit inspection unavailable");
  expect(await handlers.tool_call({ toolName: "read" }, ctx)).toBeUndefined();
});
