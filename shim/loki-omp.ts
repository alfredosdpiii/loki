import { fileURLToPath } from "node:url";
import { installContext, installGuard, directPaths, localTarget, type ExtensionApi } from "./loki.ts";

type NativeModule = { editInspect?: (mode: string, payload: string) => unknown };

const EDIT_MODES = ["replace", "patch", "apply_patch", "hashline", "sloppy"] as const;

function ompTarget(value: unknown, cwd: string): string {
  const path = localTarget(value, cwd);
  if (path.includes(":")) throw new Error("loki: unsupported target syntax");
  return path;
}

function collectFileOps(fileOps: unknown[], cwd: string, paths: Set<string>) {
  for (const op of fileOps) {
    if (!op || typeof op !== "object") throw new Error("loki: OMP edit inspection unavailable");
    const record = op as { path?: unknown; to?: unknown };
    paths.add(ompTarget(record.path, cwd));
    if (record.to !== undefined && record.to !== null) paths.add(ompTarget(record.to, cwd));
  }
}

function collectInspection(inspection: unknown, cwd: string, paths: Set<string>) {
  if (!inspection || typeof inspection !== "object") throw new Error("loki: OMP edit inspection unavailable");
  const { paths: inspectedPaths, fileOps } = inspection as { paths?: unknown; fileOps?: unknown };
  if (!Array.isArray(inspectedPaths) || !Array.isArray(fileOps)) throw new Error("loki: OMP edit inspection unavailable");
  for (const path of inspectedPaths) paths.add(ompTarget(path, cwd));
  collectFileOps(fileOps, cwd, paths);
}

function extractOmpPaths(native: NativeModule | undefined, toolName: string, input: unknown, cwd: string): string[] {
  if (toolName === "write") return directPaths(toolName, input, cwd).map(path => ompTarget(path, cwd));
  if (!native?.editInspect) throw new Error("loki: OMP edit inspection unavailable");
  const paths = new Set<string>();
  const payload = JSON.stringify(input);
  let lastError: unknown;
  for (const mode of EDIT_MODES) {
    let inspection: unknown;
    try {
      inspection = native.editInspect(mode, payload);
    } catch (error) {
      lastError = error;
      continue;
    }
    collectInspection(inspection, cwd, paths);
  }
  if (!paths.size) throw new Error("loki: OMP edit inspection unavailable", { cause: lastError });
  return [...paths];
}

export default async function (api: ExtensionApi) {
  const root = fileURLToPath(new URL("../../", import.meta.url));
  const native = await import("@oh-my-pi/pi-natives").catch(() => undefined);
  installContext(api, root);
  installGuard(api, root, (toolName, input, cwd) => extractOmpPaths(native, toolName, input, cwd), "omp");
}
