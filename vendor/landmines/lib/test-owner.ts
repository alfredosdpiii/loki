import { existsSync, readFileSync, realpathSync, statSync } from "node:fs";
import { basename, dirname, extname, join, relative, resolve as resolvePath, sep } from "node:path";

const companion = /\.(?:test|e2e|fixture|test-utils)\./u;
const testDirectories = new Set(["test", "tests", "__tests__"]);
const sourceExtensions = [".ts", ".tsx", ".mts", ".cts", ".js", ".jsx", ".mjs", ".cjs"];
const extensionAliases: Record<string, readonly string[]> = {
  ".js": [".ts", ".tsx", ".js"],
  ".mjs": [".mts", ".mjs"],
  ".cjs": [".cts", ".cjs"],
};

function isFile(path: string): boolean {
  try {
    return statSync(path).isFile();
  } catch {
    return false;
  }
}

function resolveRelativeFile(importer: string, specifier: string): string | undefined {
  if (!specifier.startsWith(".")) {
    return undefined;
  }
  const base = resolvePath(dirname(importer), specifier);
  const ext = extname(base);
  const candidates: string[] = [];
  if (ext && ext in extensionAliases) {
    const stem = base.slice(0, -ext.length);
    for (const mapped of extensionAliases[ext] ?? []) {
      candidates.push(`${stem}${mapped}`);
    }
  } else {
    candidates.push(base);
    for (const candidateExt of sourceExtensions) {
      candidates.push(`${base}${candidateExt}`);
    }
    for (const candidateExt of sourceExtensions) {
      candidates.push(join(base, `index${candidateExt}`));
    }
  }
  return candidates.find(isFile);
}

export function packageDirectory(directory: string) {
  let current = directory;

  while (!existsSync(join(current, "package.json"))) {
    const parent = dirname(current);

    if (parent === current) {
      return current;
    }

    current = parent;
  }

  return current;
}

function stripComments(source: string): string {
  return source.replace(/\/\*[\s\S]*?\*\/|\/\/[^\n]*/gu, "");
}

function companionImports(filename: string) {
  let raw: string;
  try {
    raw = readFileSync(filename, "utf8");
  } catch {
    return;
  }
  const text = stripComments(raw);
  const imports: string[] = [];
  const staticRe = /(?:^|[;\n])\s*(import|export)\s+(?!type\b)(?:[^;\n]*?\bfrom\s+)?["']([^"'\n]+)["']/gu;
  for (const match of text.matchAll(staticRe)) {
    const spec = match[2];
    if (spec) {
      imports.push(spec);
    }
  }
  const dynamicRe = /\bimport\s*\(\s*["']([^"'\n]+)["']\s*\)/gu;
  for (const match of text.matchAll(dynamicRe)) {
    const spec = match[1];
    if (spec) {
      imports.push(spec);
    }
  }
  return imports;
}

function companionDirectory(filename: string, source: string) {
  const parts = relative(source, dirname(filename)).split(sep);
  const support = parts.findIndex((part) => testDirectories.has(part));

  return support === -1
    ? dirname(filename)
    : join(source, ...parts.slice(0, support));
}

export function testOwner(testFilename: string, imports: readonly string[]) {
  const filename = realpathSync(testFilename);
  const directory = packageDirectory(dirname(filename));
  const source = join(directory, "src");
  const visited = new Set<string>([filename]);
  const local = new Set<string>();
  const invalidCompanions = new Set<string>();
  const inferredOwners = new Set<string>();
  const ambiguousOwners = new Set<string>();

  function resolve(importer: string, specifiers: readonly string[]) {
    return specifiers.flatMap((specifier) => {
      const target = resolveRelativeFile(importer, specifier);

      if (
        !target?.startsWith(`${directory}${sep}`) ||
        !/\.[cm]?[jt]sx?$/u.test(target) ||
        /\.d\.[cm]?ts$/u.test(target) ||
        packageDirectory(dirname(target)) !== directory
      ) {
        return [];
      }

      return [target];
    });
  }

  function isCompanion(target: string) {
    return (
      companion.test(target) ||
      relative(source, target)
        .split(sep)
        .slice(0, -1)
        .some((part) => testDirectories.has(part))
    );
  }

  function addSubject(target: string) {
    if (
      !["index", "app", "worker"].some(
        (entry) =>
          dirname(target) === source &&
          basename(target, extname(target)) === entry,
      )
    ) {
      local.add(dirname(target));
    }
  }

  function collectCompanion(target: string, owner: string) {
    if (visited.has(target)) {
      return;
    }

    visited.add(target);

    const nested = companionImports(target);

    if (nested === undefined) {
      invalidCompanions.add(target);

      return;
    }

    for (const imported of resolve(target, nested)) {
      if (isCompanion(imported)) {
        if (companionDirectory(imported, source) === owner) {
          collectCompanion(imported, owner);
        } else {
          ambiguousOwners.add(owner);
        }
      } else if (dirname(imported) === owner) {
        inferredOwners.add(owner);
      } else {
        ambiguousOwners.add(owner);
      }

      if (!isCompanion(imported) && isOwnedTest(filename, dirname(imported))) {
        addSubject(imported);
      }
    }
  }

  const resolved = resolve(filename, imports);

  const companions = resolved.filter(
    (target) => target.startsWith(`${source}${sep}`) && isCompanion(target),
  );

  const packageHarness = resolved.some(
    (target) => !target.startsWith(`${source}${sep}`) && isCompanion(target),
  );

  const ownedCompanions = companions.filter((target) =>
    isOwnedTest(filename, companionDirectory(target, source)),
  );

  for (const target of resolved.filter(
    (candidate) =>
      candidate.startsWith(`${source}${sep}`) && !isCompanion(candidate),
  )) {
    addSubject(target);
  }

  for (const target of ownedCompanions.length > 0
    ? ownedCompanions
    : companions) {
    collectCompanion(target, companionDirectory(target, source));
  }

  if (invalidCompanions.size > 0) {
    return;
  }

  for (const owner of inferredOwners) {
    if (
      isOwnedTest(filename, owner) ||
      (!ambiguousOwners.has(owner) && !packageHarness)
    ) {
      local.add(owner);
    }
  }

  const owned = [...local].find((owner) => isOwnedTest(filename, owner));

  if (owned !== undefined) {
    return owned;
  }

  const [first] = local;

  if (first === undefined) {
    return;
  }

  let owner = first;

  for (const target of local) {
    while (target !== owner && !target.startsWith(`${owner}${sep}`)) {
      owner = dirname(owner);
    }
  }

  return owner !== source && local.has(owner) ? owner : undefined;
}

export function isOwnedTest(filename: string, owner: string) {
  const location = relative(owner, dirname(realpathSync(filename))).split(sep);

  return location[0] === "" || testDirectories.has(location[0] ?? "");
}
