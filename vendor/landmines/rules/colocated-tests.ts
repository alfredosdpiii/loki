import { relative } from "node:path";
import { defineRule } from "@oxlint/plugins";

import { isOwnedTest, testOwner } from "../lib/test-owner.ts";

export const colocatedTests = defineRule({
  meta: {
    type: "suggestion",
    schema: [],
    docs: {
      description:
        "Keep module tests beside their implementation or in its local tests directory.",
    },
    messages: {
      detached:
        "This test has an implementation owner in {{owner}}. Move it beside that implementation or into its local tests directory, including any test-specific fixtures and snapshots.",
    },
  },
  create(context) {
    const filename = context.physicalFilename;
    const imports: string[] = [];

    if (!/\.test\.[cm]?[jt]sx?$/u.test(filename)) {
      return {};
    }

    return {
      ImportDeclaration(node) {
        const typeOnly =
          node.importKind === "type" ||
          (node.specifiers.length > 0 &&
            node.specifiers.every(
              (specifier) =>
                specifier.type === "ImportSpecifier" &&
                specifier.importKind === "type",
            ));

        if (!typeOnly) {
          imports.push(node.source.value);
        }
      },
      ImportExpression(node) {
        if (node.source.type === "Literal" && typeof node.source.value === "string") {
          imports.push(node.source.value);
        }
      },
      "Program:exit"(node) {
        const owner = testOwner(filename, imports);

        if (owner !== undefined && !isOwnedTest(filename, owner)) {
          context.report({
            node,
            messageId: "detached",
            data: { owner: relative(context.cwd, owner) },
          });
        }
      },
    };
  },
});
