import { fileURLToPath } from "node:url";
import { installContext, installGuard, directPaths, localTarget, type ExtensionApi } from "./loki.ts";

export default async function (api: ExtensionApi) {
  const root = fileURLToPath(new URL("../../", import.meta.url));
  const native = await import("@oh-my-pi/pi-natives").catch(() => undefined);
  installContext(api, root);
  installGuard(api, root, (toolName, input, cwd) => {
    const target = (value: unknown) => {
      if (typeof value !== "string" || !value || value.includes("\0")) throw new Error("loki: invalid target path");
      const path = localTarget(value, cwd);
      if (path.includes(":")) throw new Error("loki: unsupported target syntax");
      return path;
    };
    if (toolName === "write") return directPaths(toolName, input, cwd).map(target);
    if (!native?.editInspect) throw new Error("loki: OMP edit inspection unavailable");
    const paths = new Set<string>();
    for (const mode of ["replace", "patch", "apply_patch", "hashline", "sloppy"]) {
      let inspection;
      try { inspection = native.editInspect(mode, JSON.stringify(input)); } catch { continue; }
      if (!inspection || !Array.isArray(inspection.paths) || !Array.isArray(inspection.fileOps)) throw new Error("loki: OMP edit inspection unavailable");
      for (const path of inspection.paths) paths.add(target(path));
      for (const op of inspection.fileOps) {
        if (!op || typeof op !== "object") throw new Error("loki: OMP edit inspection unavailable");
        paths.add(target(op.path));
        if (op.to !== undefined && op.to !== null) paths.add(target(op.to));
      }
    }
    if (!paths.size) throw new Error("loki: OMP edit inspection unavailable");
    return [...paths];
  }, "omp");
}
