import { defineRule } from "@oxlint/plugins";
import type { ESTree } from "@oxlint/plugins";

import { allowlistSchema, reportAllowed } from "../lib/allowlist.ts";

const testFunctions = new Set(["test", "it", "describe", "suite"]);
const configTimeouts = new Set(["testTimeout", "hookTimeout"]);
const testTimeouts = new Set(["timeout"]);

function keyName(property: ESTree.Node) {
  if (property.type !== "Property" || property.computed) {
    return null;
  }

  if (property.key.type === "Identifier") {
    return property.key.name;
  }

  return property.key.type === "Literal" ? String(property.key.value) : null;
}

function rootName(initial: ESTree.Node) {
  let node = initial;

  while (node.type === "MemberExpression" || node.type === "CallExpression") {
    node = node.type === "MemberExpression" ? node.object : node.callee;
  }

  return node.type === "Identifier" ? node.name : null;
}

function memberName(node: ESTree.Node) {
  return node.type === "MemberExpression" &&
    !node.computed &&
    node.property.type === "Identifier"
    ? node.property.name
    : null;
}

function testCall(node: ESTree.CallExpression) {
  const name = rootName(node.callee);
  const member = memberName(node.callee);

  return (
    name !== null &&
    testFunctions.has(name) &&
    member !== "each" &&
    member !== "for" &&
    member !== "extend" &&
    member !== "scoped" &&
    member !== "override"
  );
}

function configCall(node: ESTree.CallExpression) {
  return (
    node.callee.type === "MemberExpression" &&
    node.callee.object.type === "Identifier" &&
    node.callee.object.name === "vi" &&
    memberName(node.callee) === "setConfig"
  );
}

export const noFlakeMasking = defineRule({
  meta: {
    type: "problem",
    schema: allowlistSchema,
    docs: {
      description:
        "Fix flaky tests at their cause instead of retrying them or raising their timeouts.",
    },
    messages: {
      retry:
        "Do not retry tests. A test that passes on rerun is a flake: wait on the event it depends on and file the failure under the flaky-test tracker.",
      timeout:
        "Do not raise a test's timeout. Wait on the event the test depends on, or move slow shared setup into a beforeAll hook.",
      stale:
        "This file now has {{count}} test timeout bumps; lower its no-flake-masking allowlist entry for {{path}} in .oxlintrc.jsonc to {{count}}, or remove the entry at 0.",
    },
  },
  create(context) {
    const timeouts: ESTree.Node[] = [];

    function inspect(node: ESTree.Node | undefined, keys: ReadonlySet<string>) {
      if (node?.type !== "ObjectExpression") {
        return;
      }

      for (const property of node.properties) {
        const key = keyName(property);

        if (key === "retry") {
          context.report({ node: property, messageId: "retry" });
        } else if (key !== null && keys.has(key)) {
          timeouts.push(property);
        }
      }
    }

    return {
      CallExpression(node) {
        if (configCall(node)) {
          inspect(node.arguments[0], configTimeouts);

          return;
        }

        if (!testCall(node)) {
          return;
        }

        const [, second, third] = node.arguments;

        inspect(second, testTimeouts);

        inspect(third, testTimeouts);

        if (
          third !== undefined &&
          second?.type !== "ObjectExpression" &&
          third.type !== "ObjectExpression" &&
          third.type !== "ArrowFunctionExpression" &&
          third.type !== "FunctionExpression"
        ) {
          timeouts.push(third);
        }
      },
      "Program:exit"(program) {
        reportAllowed(context, program, timeouts, "timeout");
      },
      Property(node) {
        if (keyName(node) === "test") {
          inspect(node.value, configTimeouts);
        }
      },
    };
  },
});
