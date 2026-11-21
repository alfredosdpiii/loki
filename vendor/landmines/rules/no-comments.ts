import { defineRule } from "@oxlint/plugins";
import type { Comment, ESTree, Scope } from "@oxlint/plugins";

const directives = [
  /^(?:eslint|oxlint)-(?:disable|enable)(?:-next-line|-line)?(?:\s|$)/u,
  /^@ts-(?:expect-error|ignore|nocheck|check)(?:\s|$)/u,
  /^(?:prettier|oxfmt)-ignore(?:-start|-end)?(?:\s|$)/u,
  /^(?:c8|v8|istanbul)\s+ignore\b/u,
  /^(?:@|#)__(?:PURE|NO_SIDE_EFFECTS|INLINE|NOINLINE)__$/u,
  /^@vite-ignore$/u,
  /^webpack(?:ChunkName|Mode|Prefetch|Preload|Ignore|Include|Exclude|Exports|FetchPriority):/u,
  /^(?:@jsx|@jsxFrag|@jsxImportSource|@jsxRuntime)\s+\S/u,
  /^\/\s*<(?:reference|amd-module|amd-dependency)\s/u,
  /^#\s*source(?:Mapping)?URL=/u,
  /^nosemgrep(?:\s|:|$)/u,
  /^(?:SPDX-License-Identifier:|@license\b)/mu,
];

function isDirective(comment: Comment) {
  const value = comment.value
    .replace(/^!/u, "")
    .replaceAll(/^\s*\*\s?/gmu, "")
    .trim();

  return (
    comment.type === "Shebang" ||
    directives.some((pattern) => pattern.test(value))
  );
}

function isAllowed(comment: Comment, prefixes: readonly string[]) {
  const value = comment.value.trimStart();

  return (
    comment.type === "Line" &&
    comment.loc.start.line === comment.loc.end.line &&
    prefixes.some(
      (prefix) =>
        value.startsWith(`${prefix}:`) &&
        value.slice(prefix.length + 1).trim() !== "",
    )
  );
}

function parseNoCommentsOptions(
  options: readonly unknown[],
): { publicApi?: string[]; allow?: string[] } {
  const first = options[0];
  if (!first || typeof first !== "object") {
    return {};
  }
  const record = first as { publicApi?: unknown; allow?: unknown };
  const result: { publicApi?: string[]; allow?: string[] } = {};
  if (Array.isArray(record.publicApi)) {
    result.publicApi = record.publicApi.filter(
      (item): item is string => typeof item === "string",
    );
  }
  if (Array.isArray(record.allow)) {
    result.allow = record.allow.filter(
      (item): item is string => typeof item === "string" && item.length > 0,
    );
  }
  return result;
}

export const noComments = defineRule({
  meta: {
    type: "suggestion",
    schema: [
      {
        type: "object",
        properties: {
          publicApi: { type: "array", items: { type: "string" } },
          allow: { type: "array", items: { type: "string", minLength: 1 } },
        },
        additionalProperties: false,
      },
    ],
    docs: {
      description:
        "Allow only functional directives, single-line comments with an allowed prefix such as WARNING:, and exported public API TSDoc.",
    },
    messages: {
      forbidden:
        "Remove this comment; express meaning in code and rationale in the PR. Keep functional directives, single-line WARNING: comments for dangerous recurring footguns, or TSDoc on exported public API symbols.",
    },
  },
  create(context) {
    const source = context.sourceCode;

    const options = parseNoCommentsOptions(context.options);
    const filename = context.physicalFilename.replaceAll("\\", "/");
    const prefixes = options.allow ?? ["WARNING"];

    const publicFile =
      options.publicApi === undefined ||
      options.publicApi.some((pattern) =>
        new RegExp(pattern, "u").test(filename),
      );

    const documented = new Set<number>();
    const declarations = new Set<ESTree.Node>();
    const members: ESTree.Node[] = [];
    const references: ESTree.TSTypeReference[] = [];

    function document(node: ESTree.Node) {
      const comments = source.getCommentsBefore(node);
      let [start] = node.range;

      while (comments.length > 0) {
        const last = comments.at(-1);

        if (!last || !isDirective(last)) {
          break;
        }

        if (source.text.slice(last.range[1], start).trim() !== "") {
          return;
        }

        [start] = last.range;

        comments.pop();
      }

      const comment = comments.at(-1);

      if (
        comment?.type === "Block" &&
        comment.value.startsWith("*") &&
        !/@(?:internal|private)\b/u.test(comment.value) &&
        source.text.slice(comment.range[1], start).trim() === ""
      ) {
        documented.add(comment.range[0]);
      }
    }

    function collectMember(node: ESTree.Node) {
      members.push(node);
    }

    function isExposed(node: ESTree.Node) {
      let ancestor = node;

      while (!declarations.has(ancestor)) {
        if (
          ancestor.type === "Program" ||
          ancestor.type === "BlockStatement" ||
          ancestor.type === "StaticBlock" ||
          ("accessibility" in ancestor &&
            (ancestor.accessibility === "private" ||
              ancestor.accessibility === "protected")) ||
          ("key" in ancestor && ancestor.key.type === "PrivateIdentifier") ||
          (ancestor.parent.type === "ArrowFunctionExpression" &&
            ancestor.parent.body === ancestor)
        ) {
          return false;
        }

        ancestor = ancestor.parent;
      }

      return true;
    }

    return {
      Property: collectMember,
      TSInterfaceDeclaration: collectMember,
      TSTypeAliasDeclaration: collectMember,
      TSPropertySignature: collectMember,
      TSMethodSignature: collectMember,
      TSCallSignatureDeclaration: collectMember,
      TSConstructSignatureDeclaration: collectMember,
      TSIndexSignature: collectMember,
      TSEnumMember: collectMember,
      MethodDefinition: collectMember,
      PropertyDefinition: collectMember,
      TSTypeReference(node) {
        references.push(node);
      },
      "Program:exit"(program) {
        if (publicFile) {
          const exportedNames = new Set<string>();

          const ambientFile =
            /\.d\.[cm]?ts$/u.test(context.physicalFilename) &&
            program.body.every(
              (node) =>
                node.type !== "ImportDeclaration" &&
                !node.type.startsWith("Export"),
            );

          for (const node of program.body) {
            if (
              ambientFile ||
              (node.type === "TSModuleDeclaration" && node.declare)
            ) {
              declarations.add(node);
            }

            if (node.type === "ExportNamedDeclaration") {
              document(node);

              if (node.declaration) {
                declarations.add(node.declaration);
              } else if (node.source === null) {
                for (const specifier of node.specifiers) {
                  if (specifier.local.type === "Identifier") {
                    exportedNames.add(specifier.local.name);
                  }
                }
              }
            } else if (node.type === "ExportDefaultDeclaration") {
              document(node);

              if (node.declaration.type === "Identifier") {
                exportedNames.add(node.declaration.name);
              } else {
                declarations.add(node.declaration);
              }
            } else if (node.type === "ExportAllDeclaration") {
              document(node);
            }
          }

          for (const node of program.body) {
            if (
              source
                .getDeclaredVariables(node)
                .some((variable) => exportedNames.has(variable.name))
            ) {
              declarations.add(node);
            }
          }

          let previousSize = -1;

          while (previousSize !== declarations.size) {
            previousSize = declarations.size;

            for (const reference of references) {
              if (
                reference.typeName.type !== "Identifier" ||
                !isExposed(reference)
              ) {
                continue;
              }

              let scope: Scope | null = source.getScope(reference);

              while (scope) {
                const variable = scope.set.get(reference.typeName.name);

                if (variable) {
                  for (const definition of variable.defs) {
                    if (
                      definition.node.type === "TSInterfaceDeclaration" ||
                      definition.node.type === "TSTypeAliasDeclaration"
                    ) {
                      declarations.add(definition.node);
                    }
                  }

                  break;
                }

                scope = scope.upper;
              }
            }
          }

          for (const node of declarations) {
            document(node);
          }

          for (const node of members) {
            if (isExposed(node)) {
              document(node);
            }
          }
        }

        for (const comment of source.getAllComments()) {
          if (
            !isDirective(comment) &&
            !isAllowed(comment, prefixes) &&
            !documented.has(comment.range[0])
          ) {
            context.report({ loc: comment.loc, messageId: "forbidden" });
          }
        }
      },
    };
  },
});
