import { defineRule } from "@oxlint/plugins";
import type { ESTree } from "@oxlint/plugins";

function isReduceCall(node: ESTree.CallExpression): boolean {
  return (
    node.callee.type === "MemberExpression" &&
    !node.callee.computed &&
    node.callee.property.type === "Identifier" &&
    (node.callee.property.name === "reduce" || node.callee.property.name === "reduceRight")
  );
}

function containsAccumulatorSpread(node: ESTree.Node | null | undefined, accName: string): boolean {
  if (!node || typeof node !== "object") return false;
  if (
    node.type === "SpreadElement" &&
    node.argument.type === "Identifier" &&
    node.argument.name === accName
  ) {
    return true;
  }
  if (
    node.type === "FunctionExpression" ||
    node.type === "ArrowFunctionExpression" ||
    node.type === "FunctionDeclaration"
  ) {
    return false;
  }
  for (const [key, value] of Object.entries(node)) {
    if (key === "parent") continue;
    if (Array.isArray(value)) {
      for (const item of value) {
        if (containsAccumulatorSpread(item as ESTree.Node, accName)) return true;
      }
    } else if (value && typeof value === "object" && "type" in value) {
      if (containsAccumulatorSpread(value as ESTree.Node, accName)) return true;
    }
  }
  return false;
}

/** Disallow spreading the accumulator inside `.reduce()`, which turns linear accumulation into O(n^2) copying. */
export const noReduceAccumulatorCopyRule = defineRule({
  meta: {
    type: "problem",
    docs: {
      description:
        "Disallow copying the reduce accumulator via object/array spread on each iteration (O(n^2) allocations).",
    },
    messages: {
      copy: "Spreading the `.reduce()` accumulator copies it on every element (O(n^2)). Mutate the freshly created accumulator or use a `for` loop / `Map`.",
    },
  },
  createOnce(context) {
    return {
      CallExpression(node) {
        if (!isReduceCall(node) || node.arguments.length === 0) return;
        const callback = node.arguments[0];
        if (
          callback.type !== "ArrowFunctionExpression" &&
          callback.type !== "FunctionExpression"
        ) {
          return;
        }
        const firstParam = callback.params[0];
        if (!firstParam || firstParam.type !== "Identifier") return;
        if (containsAccumulatorSpread(callback.body, firstParam.name)) {
          context.report({ node: callback, messageId: "copy" });
        }
      },
    };
  },
});
