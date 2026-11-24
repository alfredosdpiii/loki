import { defineRule } from "@oxlint/plugins";
import type { ESTree } from "@oxlint/plugins";

function isMethodCall(node: ESTree.Node | null | undefined, method: string): node is ESTree.CallExpression {
  return (
    node?.type === "CallExpression" &&
    node.callee.type === "MemberExpression" &&
    !node.callee.computed &&
    node.callee.property.type === "Identifier" &&
    node.callee.property.name === method
  );
}

/** Disallow chaining `.filter(...).map(...)` which allocates an unnecessary intermediate array. */
export const noArrayFilterMapRule = defineRule({
  meta: {
    type: "suggestion",
    docs: {
      description:
        "Disallow chaining .filter().map() on arrays; use .flatMap() or a single loop to avoid extra allocations.",
    },
    messages: {
      filterMap:
        "Chained `.filter(...).map(...)` traverses and allocates twice. Combine them into `.flatMap(...)` or a single `for` loop.",
    },
  },
  createOnce(context) {
    return {
      CallExpression(node) {
        if (!isMethodCall(node, "map")) return;
        const receiver = (node.callee as ESTree.MemberExpression).object;
        if (isMethodCall(receiver, "filter")) {
          context.report({ node, messageId: "filterMap" });
        }
      },
    };
  },
});
