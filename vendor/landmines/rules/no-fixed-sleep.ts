import { defineRule } from "@oxlint/plugins";
import type { ESTree } from "@oxlint/plugins";

import { allowlistProperties, reportAllowed } from "../lib/allowlist.ts";

const defaultRunNow = ["act", "waitFor", "then", "catch", "finally", "step"];

function parseNoFixedSleepOptions(options: readonly unknown[]): { runNow?: string[] } {
  const first = options[0];
  if (!first || typeof first !== "object" || !("runNow" in first)) {
    return {};
  }
  const runNow = (first as { runNow?: unknown }).runNow;
  if (!Array.isArray(runNow)) {
    return {};
  }
  return { runNow: runNow.filter((item): item is string => typeof item === "string") };
}

const testCallees = new Set([
  "test",
  "it",
  "beforeEach",
  "afterEach",
  "beforeAll",
  "afterAll",
]);

const timerModules = new Set(["node:timers/promises", "timers/promises"]);

function isMember(node: ESTree.Node, object: string, property: string) {
  return (
    node.type === "MemberExpression" &&
    node.object.type === "Identifier" &&
    node.object.name === object &&
    node.property.type === "Identifier" &&
    !node.computed &&
    node.property.name === property
  );
}

function isSetTimeout(node: ESTree.Node) {
  return (
    (node.type === "Identifier" && node.name === "setTimeout") ||
    isMember(node, "globalThis", "setTimeout") ||
    isMember(node, "window", "setTimeout")
  );
}

const calleeRoot: (node: ESTree.Node) => string | undefined = (node) => {
  if (node.type === "CallExpression") {
    return calleeRoot(node.callee);
  }

  if (node.type === "MemberExpression") {
    return calleeRoot(node.object);
  }

  if (node.type === "TaggedTemplateExpression") {
    return calleeRoot(node.tag);
  }

  return node.type === "Identifier" ? node.name : undefined;
};

function calleeName(node: ESTree.Node) {
  if (node.type === "Identifier") {
    return node.name;
  }

  return node.type === "MemberExpression" &&
    !node.computed &&
    node.property.type === "Identifier"
    ? node.property.name
    : undefined;
}

const inTestBody: (
  node: ESTree.Node,
  runNow: ReadonlySet<string>,
) => boolean = (node, runNow) => {
  let current: ESTree.Node | null = node.parent;

  while (
    current &&
    current.type !== "ArrowFunctionExpression" &&
    current.type !== "FunctionExpression" &&
    current.type !== "FunctionDeclaration"
  ) {
    current = current.parent;
  }

  const call = current?.parent;

  if (call?.type !== "CallExpression") {
    return false;
  }

  if (testCallees.has(calleeRoot(call.callee) ?? "")) {
    return true;
  }

  return runNow.has(calleeName(call.callee) ?? "") && inTestBody(call, runNow);
};

function scheduled(body: ESTree.Node | null) {
  if (body?.type !== "BlockStatement") {
    return body;
  }

  const [statement, ...rest] = body.body;

  return statement?.type === "ExpressionStatement" && rest.length === 0
    ? statement.expression
    : null;
}

function resolvesAfterTimeout(node: ESTree.NewExpression) {
  const [executor] = node.arguments;

  if (
    !executor ||
    (executor.type !== "ArrowFunctionExpression" &&
      executor.type !== "FunctionExpression")
  ) {
    return false;
  }

  const [resolve] = executor.params;

  if (resolve?.type !== "Identifier") {
    return false;
  }

  const call = scheduled(executor.body);

  if (call?.type !== "CallExpression" || !isSetTimeout(call.callee)) {
    return false;
  }

  const [handler] = call.arguments;

  if (handler?.type === "Identifier") {
    return handler.name === resolve.name;
  }

  if (
    handler?.type !== "ArrowFunctionExpression" &&
    handler?.type !== "FunctionExpression"
  ) {
    return false;
  }

  const settle = scheduled(handler.body);

  return (
    settle?.type === "CallExpression" &&
    settle.callee.type === "Identifier" &&
    settle.callee.name === resolve.name
  );
}

export const noFixedSleep = defineRule({
  meta: {
    type: "problem",
    schema: [
      {
        type: "object",
        properties: {
          ...allowlistProperties,
          runNow: { type: "array", items: { type: "string" } },
        },
        additionalProperties: false,
      },
    ],
    docs: {
      description:
        "Disallow awaiting a fixed real-time sleep in a test or hook body.",
    },
    messages: {
      sleep:
        "Replace this fixed sleep with a signal: await the operation itself or a promise its handler resolves. To move time, use vi.useFakeTimers() and advance it. A sleep guesses how long real work takes and fails under CPU load.",
      stale:
        "This file now has {{count}} fixed sleeps; lower its no-fixed-sleep allowlist entry for {{path}} in .oxlintrc.jsonc to {{count}}, or remove the entry at 0.",
    },
  },
  create(context) {
    const options = parseNoFixedSleepOptions(context.options);
    const runNow = new Set(options.runNow ?? defaultRunNow);
    const timers = new Set<string>();
    const sleeps: ESTree.Node[] = [];
    let fakeTimers = false;

    function isSleep(node: ESTree.Node) {
      if (node.type === "NewExpression") {
        return (
          node.callee.type === "Identifier" &&
          node.callee.name === "Promise" &&
          resolvesAfterTimeout(node)
        );
      }

      if (node.type !== "CallExpression") {
        return false;
      }

      return (
        (node.callee.type === "Identifier" && timers.has(node.callee.name)) ||
        isMember(node.callee, "scheduler", "wait") ||
        isMember(node.callee, "Bun", "sleep")
      );
    }

    return {
      ImportDeclaration(node) {
        if (!timerModules.has(node.source.value)) {
          return;
        }

        for (const specifier of node.specifiers) {
          if (
            specifier.type === "ImportSpecifier" &&
            specifier.imported.type === "Identifier" &&
            specifier.imported.name === "setTimeout"
          ) {
            timers.add(specifier.local.name);
          }
        }
      },
      CallExpression(node) {
        if (isMember(node.callee, "vi", "useFakeTimers")) {
          fakeTimers = true;
        }
      },
      AwaitExpression(node) {
        if (isSleep(node.argument) && inTestBody(node, runNow)) {
          sleeps.push(node);
        }
      },
      "Program:exit"(program) {
        reportAllowed(context, program, fakeTimers ? [] : sleeps, "sleep");
      },
    };
  },
});
