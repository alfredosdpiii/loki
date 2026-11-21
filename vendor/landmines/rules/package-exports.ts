import { existsSync, readFileSync } from "node:fs";
import { dirname, join, posix } from "node:path";
import { defineRule } from "@oxlint/plugins";

import { packageDirectory } from "../lib/test-owner.ts";

function unrestrictedSourceExports(value: unknown) {
  const pending: unknown[] = [value];
  const violations = new Set<string>();

  while (pending.length > 0) {
    const current = pending.pop();

    if (typeof current === "string") {
      if (/^(?:src\/)?\*(?:\.[cm]?[jt]sx?)?$/u.test(posix.normalize(current))) {
        violations.add(current);
      }

      continue;
    }

    if (Array.isArray(current)) {
      pending.push(...current);

      continue;
    }

    if (current && typeof current === "object") {
      pending.push(...Object.values(current));
    }
  }

  return [...violations];
}

export const packageExports = defineRule({
  meta: {
    type: "problem",
    schema: [],
    docs: {
      description:
        "Declare intentional package interfaces instead of unrestricted source exports.",
    },
    messages: {
      unrestricted:
        "{{manifest}} exposes arbitrary implementation files through {{targets}}. Declare explicit entrypoints or named public namespaces in package.json.",
    },
  },
  create(context) {
    const directory = packageDirectory(dirname(context.physicalFilename));
    const path = join(directory, "package.json");

    if (!existsSync(path)) {
      return {};
    }

    let manifest: unknown;
    try {
      manifest = JSON.parse(readFileSync(path, "utf8"));
    } catch {
      return {};
    }
    const exportsField =
      manifest && typeof manifest === "object" && "exports" in manifest
        ? (manifest as { exports?: unknown }).exports
        : undefined;
    const targets = unrestrictedSourceExports(exportsField);

    return {
      Program(node) {
        if (targets.length > 0) {
          context.report({
            node,
            messageId: "unrestricted",
            data: { manifest: path, targets: targets.join(", ") },
          });
        }
      },
    };
  },
});
