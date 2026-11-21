import { defineRule } from "@oxlint/plugins";
import type { ESTree, Scope, SourceCode, Variable } from "@oxlint/plugins";

import { allowlistSchema, reportAllowed } from "../lib/allowlist.ts";

const starters = new Map([
  ["setupServer", "listen"],
  ["setupWorker", "start"],
]);

function variableOf(source: SourceCode, node: ESTree.Node, name: string) {
  for (
    let scope: Scope | null = source.getScope(node);
    scope !== null;
    scope = scope.upper
  ) {
    const variable = scope.set.get(name);

    if (variable) {
      return variable;
    }
  }

  return null;
}

function mswFactory(source: SourceCode, node: ESTree.Node | null | undefined) {
  if (node?.type !== "CallExpression" || node.callee.type !== "Identifier") {
    return null;
  }

  for (const { node: definition, parent } of variableOf(
    source,
    node.callee,
    node.callee.name,
  )?.defs ?? []) {
    if (
      definition.type === "ImportSpecifier" &&
      parent?.type === "ImportDeclaration" &&
      /^msw(?:\/|$)/u.test(parent.source.value)
    ) {
      const name =
        definition.imported.type === "Identifier"
          ? definition.imported.name
          : definition.imported.value;

      return starters.has(name) ? name : null;
    }
  }

  return null;
}

function assignedValues(variable: Variable) {
  return variable.references.flatMap((reference) =>
    reference.isWrite() && reference.writeExpr ? [reference.writeExpr] : [],
  );
}

function serverFactory(source: SourceCode, node: ESTree.Node) {
  if (node.type !== "Identifier") {
    return mswFactory(source, node);
  }

  const variable = variableOf(source, node, node.name);

  if (!variable) {
    return null;
  }

  const factories = new Set(
    assignedValues(variable).flatMap((value) => {
      const factory = mswFactory(source, value);

      return factory === null ? [] : [factory];
    }),
  );

  const [factory] = factories;

  return factories.size === 1 && factory !== undefined ? factory : null;
}

function keyName(property: ESTree.ObjectProperty) {
  if (property.computed) {
    return null;
  }

  if (property.key.type === "Identifier") {
    return property.key.name;
  }

  return property.key.type === "Literal" &&
    typeof property.key.value === "string"
    ? property.key.value
    : null;
}

const unhandledOptions = new Set(["onUnhandledRequest", "onUnhandledFrame"]);

function inlineHandler(node: ESTree.Node) {
  return (
    node.type === "ArrowFunctionExpression" ||
    node.type === "FunctionExpression"
  );
}

function namedHandler(source: SourceCode, node: ESTree.Node) {
  if (node.type !== "Identifier") {
    return false;
  }

  const variable = variableOf(source, node, node.name);

  return (
    variable !== null &&
    variable.defs.length > 0 &&
    variable.defs.every(
      ({ type }) => type === "FunctionName" || type === "Variable",
    ) &&
    assignedValues(variable).every((value) => inlineHandler(value)) &&
    variable.defs.some(
      ({ type, node: definition }) =>
        type === "FunctionName" ||
        (definition.type === "VariableDeclarator" &&
          definition.init !== null &&
          inlineHandler(definition.init)),
    )
  );
}

function strict(source: SourceCode, node: ESTree.Node | undefined) {
  return (
    node?.type === "ObjectExpression" &&
    node.properties.some(
      (property) =>
        property.type === "Property" &&
        unhandledOptions.has(keyName(property) ?? "") &&
        ((property.value.type === "Literal" &&
          property.value.value === "error") ||
          inlineHandler(property.value) ||
          namedHandler(source, property.value)),
    )
  );
}

export const strictMsw = defineRule({
  meta: {
    type: "problem",
    schema: allowlistSchema,
    docs: {
      description:
        "Fail tests on requests that no MSW handler covers instead of letting them reach the network.",
    },
    messages: {
      lenient:
        'Start MSW with { onUnhandledFrame: "error" } (msw 3) or { onUnhandledRequest: "error" } (msw 2). Add a handler for every request the test makes, with passthrough() for local origins the test owns.',
      stale:
        "This file now has {{count}} lenient MSW starts; lower its strict-msw allowlist entry for {{path}} in .oxlintrc.jsonc to {{count}}, or remove the entry at 0.",
    },
  },
  create(context) {
    const source = context.sourceCode;

    const lenientStarts: ESTree.Node[] = [];

    return {
      CallExpression(node) {
        const { callee } = node;

        if (
          callee.type !== "MemberExpression" ||
          callee.computed ||
          callee.property.type !== "Identifier"
        ) {
          return;
        }

        const factory = serverFactory(source, callee.object);

        if (
          factory !== null &&
          starters.get(factory) === callee.property.name &&
          !strict(source, node.arguments[0])
        ) {
          lenientStarts.push(node);
        }
      },
      "Program:exit"(program) {
        reportAllowed(context, program, lenientStarts, "lenient");
      },
    };
  },
});
