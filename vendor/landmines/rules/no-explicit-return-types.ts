import { defineRule } from "@oxlint/plugins";
import type { ESTree } from "@oxlint/plugins";

export const noExplicitReturnTypes = defineRule({
  meta: {
    type: "suggestion",
    schema: [],
    docs: {
      description: "Infer return types on function implementations.",
    },
    messages: {
      noExplicitReturnType:
        "Remove the explicit return type and let it be inferred; pin a contract with a typed variable or `satisfies` at the return site instead.",
    },
  },
  create(context) {
    function check(node: ESTree.Function | ESTree.ArrowFunctionExpression) {
      if (
        node.body !== null &&
        node.returnType !== undefined &&
        node.returnType !== null &&
        node.returnType.typeAnnotation.type !== "TSTypePredicate" &&
        node.returnType.typeAnnotation.type !== "TSNeverKeyword"
      ) {
        context.report({
          node: node.returnType,
          messageId: "noExplicitReturnType",
        });
      }
    }

    return {
      FunctionDeclaration: check,
      FunctionExpression: check,
      ArrowFunctionExpression: check,
    };
  },
});
