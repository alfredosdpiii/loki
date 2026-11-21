import type { Context, ESTree } from "@oxlint/plugins";

export const allowlistProperties = {
  allow: {
    type: "object" as const,
    additionalProperties: { type: "integer" as const, minimum: 1 },
  },
};

export const allowlistSchema = [
  {
    type: "object" as const,
    properties: allowlistProperties,
    additionalProperties: false,
  },
];

function parseAllowlist(options: readonly unknown[]): Record<string, number> {
  const first = options[0];
  if (!first || typeof first !== "object" || !("allow" in first)) {
    return {};
  }
  const allow = (first as { allow?: unknown }).allow;
  if (!allow || typeof allow !== "object") {
    return {};
  }
  const result: Record<string, number> = {};
  for (const [key, value] of Object.entries(allow)) {
    if (typeof value === "number" && Number.isInteger(value) && value >= 1) {
      result[key] = value;
    }
  }
  return result;
}

function allowance(context: Context) {
  const filename = context.physicalFilename.replaceAll("\\", "/");
  const allow = parseAllowlist(context.options);

  return Object.entries(allow).find(
    ([path]) => filename === path || filename.endsWith(`/${path}`),
  );
}

export function reportAllowed(
  context: Context,
  program: ESTree.Program,
  violations: readonly ESTree.Node[],
  messageId: string,
) {
  const [path, count] = allowance(context) ?? ["", 0];

  if (violations.length < count) {
    context.report({
      node: program,
      messageId: "stale",
      data: { path, count: String(violations.length) },
    });

    return;
  }

  if (violations.length === count) {
    return;
  }

  for (const node of violations) {
    context.report({ node, messageId });
  }
}
