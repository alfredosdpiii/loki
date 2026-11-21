import { defineRule } from "@oxlint/plugins";
import type { ESTree, Scope, SourceCode, Variable } from "@oxlint/plugins";

const replacements = new Set([
  "mockImplementation",
  "mockImplementationOnce",
  "mockReturnValue",
  "mockReturnValueOnce",
  "mockResolvedValue",
  "mockResolvedValueOnce",
  "mockRejectedValue",
  "mockRejectedValueOnce",
  "mockReturnThis",
  "withImplementation",
  "mockStepResult",
  "mockStepError",
]);

const tauriMockMethods = new Set([
  "mockIPC",
  "mockWindows",
  "mockConvertFileSrc",
]);

const frameworkReplacements = new Set([
  "stubGlobal",
  "mock",
  "doMock",
  "unstable_mockModule",
  "importMock",
  "mockObject",
  "createMockFromModule",
  "genMockFromModule",
  "setMock",
  "replaceProperty",
  "enableAutomock",
]);

const replacementGlobals = new Set([
  "AbortController",
  "AbortSignal",
  "fetch",
  "isTauri",
  "__TAURI_INTERNALS__",
  "document",
  "CSS",
  "scrollTo",
  "scrollBy",
  "visualViewport",
  "addEventListener",
  "removeEventListener",
  "dispatchEvent",
  "CompressionStream",
  "DecompressionStream",
  "Worker",
  "SharedWorker",
  "WebSocket",
  "XMLHttpRequest",
  "ResizeObserver",
  "IntersectionObserver",
  "MutationObserver",
  "requestIdleCallback",
  "cancelIdleCallback",
  "requestAnimationFrame",
  "cancelAnimationFrame",
  "localStorage",
  "sessionStorage",
  "navigator",
  "Notification",
  "matchMedia",
  "open",
  "performance",
  "screen",
  "crypto",
  "Date",
  "FileReader",
  "BroadcastChannel",
  "innerWidth",
  "innerHeight",
  "devicePixelRatio",
]);

const documentReplacements = new Set([
  "querySelector",
  "querySelectorAll",
  "getElementById",
  "createElement",
  "addEventListener",
  "removeEventListener",
  "dispatchEvent",
  "visibilityState",
  "hidden",
  "hasFocus",
  "modelContext",
]);

const navigatorReplacements = new Set([
  "clipboard",
  "permissions",
  "storage",
  "serviceWorker",
  "gpu",
  "credentials",
  "userAgent",
  "userAgentData",
  "webdriver",
  "platform",
  "onLine",
  "modelContext",
]);

const storageReplacements = new Set([
  "getItem",
  "setItem",
  "removeItem",
  "clear",
  "key",
  "length",
]);

const nestedReplacements = new Map<string, ReadonlySet<string>>([
  [
    "FileReader.prototype",
    new Set([
      "abort",
      "readAsArrayBuffer",
      "readAsBinaryString",
      "readAsDataURL",
      "readAsText",
    ]),
  ],
  [
    "IntersectionObserver.prototype",
    new Set(["observe", "unobserve", "disconnect", "takeRecords"]),
  ],
  ["ResizeObserver.prototype", new Set(["observe", "unobserve", "disconnect"])],
  [
    "MutationObserver.prototype",
    new Set(["observe", "disconnect", "takeRecords"]),
  ],
  ["AbortController.prototype", new Set(["abort", "signal"])],
  ["AbortSignal", new Set(["abort", "any", "timeout"])],
  ["AbortSignal.prototype", new Set(["aborted", "reason", "throwIfAborted"])],
  ["Date", new Set(["now"])],
  ["Math", new Set(["random"])],
  ["performance", new Set(["now"])],
  ["crypto", new Set(["randomUUID", "getRandomValues"])],
  ["history", new Set(["pushState", "replaceState", "go", "back", "forward"])],
  ["Storage.prototype", storageReplacements],
  ["localStorage", storageReplacements],
  ["sessionStorage", storageReplacements],
  ["navigator.clipboard", new Set(["read", "readText", "write", "writeText"])],
  [
    "navigator.credentials",
    new Set(["get", "create", "store", "preventSilentAccess"]),
  ],
  ["navigator.permissions", new Set(["query"])],
  [
    "navigator.storage",
    new Set(["estimate", "persist", "persisted", "getDirectory"]),
  ],
  ["navigator.userAgentData", new Set(["getHighEntropyValues", "toJSON"])],
]);

function propertyName(source: SourceCode, node: ESTree.Node) {
  if (node.type !== "MemberExpression") {
    return null;
  }

  if (!node.computed && node.property.type === "Identifier") {
    return node.property.name;
  }

  return node.computed ? literalKey(source, node.property) : null;
}

function initializedOnce(variable: Variable) {
  return (
    variable.defs.length === 1 &&
    variable.references.every(
      (reference) => !reference.isWrite() || reference.init,
    )
  );
}

function constantValue(source: SourceCode, node: ESTree.Node) {
  if (node.type !== "Identifier") {
    return null;
  }

  for (
    let scope: Scope | null = source.getScope(node);
    scope !== null;
    scope = scope.upper
  ) {
    const variable = scope.set.get(node.name);

    if (!variable || variable.defs.length === 0) {
      continue;
    }

    for (const { node: definition, parent, type } of variable.defs) {
      if (
        type === "FunctionName" &&
        definition.type === "FunctionDeclaration" &&
        initializedOnce(variable)
      ) {
        return definition;
      }

      if (
        definition.type === "VariableDeclarator" &&
        definition.id.type === "Identifier" &&
        parent?.type === "VariableDeclaration" &&
        initializedOnce(variable)
      ) {
        return definition.init;
      }
    }

    break;
  }

  return null;
}

function lexicalVariable(source: SourceCode, node: ESTree.Node) {
  if (node.type !== "Identifier") {
    return null;
  }

  for (
    let scope: Scope | null = source.getScope(node);
    scope !== null;
    scope = scope.upper
  ) {
    const variable = scope.set.get(node.name);

    if (variable) {
      return variable;
    }
  }

  return null;
}

function sameMember(source: SourceCode, left: ESTree.Node, right: ESTree.Node) {
  let first = resolvedConstant(source, left);
  let second = resolvedConstant(source, right);
  const seen = new Set<ESTree.Node>();

  while (!seen.has(first)) {
    seen.add(first);

    if (first === second) {
      return true;
    }

    if (first.type === "Identifier" && second.type === "Identifier") {
      return (
        first.name === second.name &&
        lexicalVariable(source, first) === lexicalVariable(source, second)
      );
    }

    if (
      first.type !== "MemberExpression" ||
      second.type !== "MemberExpression"
    ) {
      return false;
    }

    const key = propertyName(source, first);

    if (key === null || key !== propertyName(source, second)) {
      return false;
    }

    first = resolvedConstant(source, first.object);

    second = resolvedConstant(source, second.object);
  }

  return false;
}

function delegatesSavedMember(
  source: SourceCode,
  initial: ESTree.Node,
  saved: Variable,
) {
  const node = resolvedConstant(source, initial);

  if (
    (node.type !== "FunctionExpression" &&
      node.type !== "FunctionDeclaration") ||
    node.async ||
    node.generator ||
    node.body?.type !== "BlockStatement"
  ) {
    return false;
  }

  const [parameter] = node.params;

  if (
    node.params.length !== 1 ||
    parameter?.type !== "RestElement" ||
    parameter.argument.type !== "Identifier"
  ) {
    return false;
  }

  const statements = node.body.body;
  const last = statements.at(-1);

  if (
    last?.type !== "ReturnStatement" ||
    statements.slice(0, -1).some((statement) => {
      if (
        statement.type !== "ExpressionStatement" ||
        statement.expression.type !== "CallExpression"
      ) {
        return true;
      }

      const { callee, args } = invokedFunction(source, statement.expression);

      if (
        callee.type === "MemberExpression" &&
        sameMember(source, callee.object, parameter.argument)
      ) {
        return true;
      }

      const path = nativePropertyPath(source, callee);
      const [target] = args;

      return (
        [
          "Reflect.set",
          "Reflect.defineProperty",
          "Reflect.deleteProperty",
          "Object.assign",
          "Object.defineProperty",
          "Object.defineProperties",
        ].includes(path ?? "") &&
        target !== undefined &&
        target !== null &&
        sameMember(source, target, parameter.argument)
      );
    })
  ) {
    return false;
  }

  const result = last.argument;

  if (result?.type !== "CallExpression") {
    return false;
  }

  const callee = resolvedConstant(source, result.callee);

  if (
    callee.type !== "MemberExpression" ||
    propertyName(source, callee) !== "apply" ||
    callee.object.type !== "Identifier" ||
    callee.object.name !== "Reflect" ||
    !unshadowed(source, callee.object)
  ) {
    return false;
  }

  const [original, receiver, args] = result.arguments;

  return (
    result.arguments.length === 3 &&
    original?.type === "Identifier" &&
    lexicalVariable(source, original) === saved &&
    receiver?.type === "ThisExpression" &&
    args?.type === "Identifier" &&
    lexicalVariable(source, parameter.argument) ===
      lexicalVariable(source, args)
  );
}

function destructuredReference(source: SourceCode, node: ESTree.Node) {
  if (node.type !== "Identifier") {
    return null;
  }

  for (
    let scope: Scope | null = source.getScope(node);
    scope !== null;
    scope = scope.upper
  ) {
    const variable = scope.set.get(node.name);

    if (!variable || variable.defs.length === 0) {
      continue;
    }

    for (const { node: definition, parent } of variable.defs) {
      if (
        definition.type !== "VariableDeclarator" ||
        definition.id.type !== "ObjectPattern" ||
        parent?.type !== "VariableDeclaration" ||
        !initializedOnce(variable) ||
        !definition.init
      ) {
        continue;
      }

      const property = definition.id.properties.find(
        (value) =>
          value.type === "Property" &&
          value.value.type === "Identifier" &&
          value.value.name === node.name,
      );

      if (property?.type !== "Property") {
        continue;
      }

      if (!property.computed && property.key.type === "Identifier") {
        return { object: definition.init, property: property.key.name };
      }

      const key = literalKey(source, property.key);

      if (key !== null) {
        return { object: definition.init, property: key };
      }
    }

    break;
  }

  return null;
}

function resolvedConstant(source: SourceCode, initial: ESTree.Node) {
  const visited = new Set<ESTree.Node>();
  let node = initial;

  while (!visited.has(node)) {
    visited.add(node);

    if (
      node.type === "TSAsExpression" ||
      node.type === "TSTypeAssertion" ||
      node.type === "TSNonNullExpression" ||
      node.type === "TSSatisfiesExpression"
    ) {
      node = node.expression;

      continue;
    }

    const value = constantValue(source, node);

    if (!value) {
      break;
    }

    node = value;
  }

  return node;
}

function literalKey(source: SourceCode, initial: ESTree.Node | undefined) {
  const node = initial ? resolvedConstant(source, initial) : undefined;

  if (node?.type === "TemplateLiteral" && node.expressions.length === 0) {
    return node.quasis[0]?.value.cooked ?? null;
  }

  return node?.type === "Literal" ? String(node.value) : null;
}

function namespaceImport(
  source: SourceCode,
  initial: ESTree.Node,
  specifier?: string,
) {
  const node = resolvedConstant(source, initial);

  if (node.type !== "Identifier") {
    return false;
  }

  for (
    let scope: Scope | null = source.getScope(node);
    scope !== null;
    scope = scope.upper
  ) {
    const variable = scope.set.get(node.name);

    if (variable === undefined || variable.defs.length === 0) {
      continue;
    }

    return variable.defs.some(
      ({ node: definition, parent }) =>
        definition.type === "ImportNamespaceSpecifier" &&
        parent?.type === "ImportDeclaration" &&
        (specifier === undefined
          ? parent.source.value === "vitest" ||
            parent.source.value === "@jest/globals"
          : parent.source.value === specifier),
    );
  }

  return false;
}

function framework(source: SourceCode, initial: ESTree.Node) {
  const node = resolvedConstant(source, initial);

  if (
    node.type === "MemberExpression" &&
    ["vi", "vitest", "jest"].includes(String(propertyName(source, node)))
  ) {
    return namespaceImport(source, node.object);
  }

  const reference = destructuredReference(source, node);

  if (reference && ["vi", "vitest", "jest"].includes(reference.property)) {
    return namespaceImport(source, reference.object);
  }

  if (node.type !== "Identifier") {
    return false;
  }

  for (
    let scope: Scope | null = source.getScope(node);
    scope !== null;
    scope = scope.upper
  ) {
    const variable = scope.set.get(node.name);

    if (variable === undefined || variable.defs.length === 0) {
      continue;
    }

    return variable.defs.some(({ node: definition, parent }) => {
      if (
        parent?.type !== "ImportDeclaration" ||
        definition.type !== "ImportSpecifier"
      ) {
        return false;
      }

      const name =
        definition.imported.type === "Identifier"
          ? definition.imported.name
          : definition.imported.value;

      return (
        (parent.source.value === "vitest" &&
          (name === "vi" || name === "vitest")) ||
        (parent.source.value === "@jest/globals" && name === "jest")
      );
    });
  }

  return ["vi", "vitest", "jest"].includes(node.name);
}

function jestFramework(source: SourceCode, callee: ESTree.Node) {
  const target = resolvedConstant(source, callee);

  if (target.type !== "MemberExpression") {
    return false;
  }

  const node = resolvedConstant(source, target.object);

  if (node.type !== "Identifier") {
    return false;
  }

  for (
    let scope: Scope | null = source.getScope(node);
    scope !== null;
    scope = scope.upper
  ) {
    const variable = scope.set.get(node.name);

    if (variable === undefined || variable.defs.length === 0) {
      continue;
    }

    return variable.defs.some(
      ({ parent }) =>
        parent?.type === "ImportDeclaration" &&
        parent.source.value === "@jest/globals",
    );
  }

  return node.name === "jest";
}

function replacementMethod(source: SourceCode, node: ESTree.Node) {
  const visited = new Set<ESTree.Node>();
  let target = node;

  while (!visited.has(target)) {
    visited.add(target);

    if (target.type === "MemberExpression") {
      const method = propertyName(source, target);

      return method !== null &&
        (replacements.has(method) || framework(source, target.object))
        ? method
        : null;
    }

    const reference = destructuredReference(source, target);

    if (
      reference &&
      (replacements.has(reference.property) ||
        framework(source, reference.object))
    ) {
      return reference.property;
    }

    if (target.type !== "Identifier") {
      return null;
    }

    let initializer: ESTree.Node | undefined;

    for (
      let scope: Scope | null = source.getScope(target);
      scope !== null;
      scope = scope.upper
    ) {
      const variable = scope.set.get(target.name);

      if (!variable || variable.defs.length === 0) {
        continue;
      }

      for (const { node: definition, parent } of variable.defs) {
        if (
          definition.type !== "VariableDeclarator" ||
          parent?.type !== "VariableDeclaration" ||
          !initializedOnce(variable) ||
          !definition.init
        ) {
          continue;
        }

        if (definition.id.type === "Identifier") {
          initializer = definition.init;

          break;
        }

        if (
          definition.id.type === "ObjectPattern" &&
          framework(source, definition.init)
        ) {
          const { name } = target;

          const property = definition.id.properties.find(
            (value) =>
              value.type === "Property" &&
              value.value.type === "Identifier" &&
              value.value.name === name,
          );

          if (property?.type === "Property") {
            if (!property.computed && property.key.type === "Identifier") {
              return property.key.name;
            }

            return literalKey(source, property.key);
          }
        }
      }

      break;
    }

    if (!initializer) {
      return null;
    }

    target = initializer;
  }

  return null;
}

function globalObject(source: SourceCode, initial: ESTree.Node) {
  const node = resolvedConstant(source, initial);

  return (
    node.type === "Identifier" &&
    ["globalThis", "window", "global", "self"].includes(node.name) &&
    unshadowed(source, node)
  );
}

function unshadowed(source: SourceCode, node: ESTree.Node) {
  if (node.type !== "Identifier") {
    return false;
  }

  for (
    let scope: Scope | null = source.getScope(node);
    scope !== null;
    scope = scope.upper
  ) {
    const variable = scope.set.get(node.name);

    if (variable !== undefined && variable.defs.length > 0) {
      return false;
    }
  }

  return true;
}

function nativePropertyPath(source: SourceCode, initial: ESTree.Node) {
  let node = resolvedConstant(source, initial);
  const seen = new Set<ESTree.Node>();
  const path: string[] = [];

  while (!seen.has(node)) {
    seen.add(node);

    const reference = destructuredReference(source, node);

    if (reference) {
      path.unshift(reference.property);

      if (globalObject(source, reference.object)) {
        return path.join(".");
      }

      node = resolvedConstant(source, reference.object);

      continue;
    }

    if (node.type === "Identifier" && unshadowed(source, node)) {
      return [node.name, ...path].join(".");
    }

    if (node.type !== "MemberExpression") {
      return null;
    }

    const property = propertyName(source, node);

    if (property === null) {
      return null;
    }

    path.unshift(property);

    if (globalObject(source, node.object)) {
      return path.join(".");
    }

    node = resolvedConstant(source, node.object);
  }

  return null;
}

function protectedProperties(source: SourceCode, initial: ESTree.Node) {
  if (globalObject(source, initial)) {
    return replacementGlobals;
  }

  const name = nativePropertyPath(source, initial);

  if (name === "document" || name === "Document.prototype") {
    return documentReplacements;
  }

  return name === "navigator" || name === "Navigator.prototype"
    ? navigatorReplacements
    : nestedReplacements.get(name ?? "");
}

function cloudflareImport(
  source: SourceCode,
  initial: ESTree.Node,
  name: string,
  specifier = "cloudflare:workers",
) {
  const node = resolvedConstant(source, initial);

  if (node.type !== "Identifier") {
    return false;
  }

  for (
    let scope: Scope | null = source.getScope(node);
    scope !== null;
    scope = scope.upper
  ) {
    const variable = scope.set.get(node.name);

    if (variable === undefined || variable.defs.length === 0) {
      continue;
    }

    return variable.defs.some(
      ({ node: definition, parent }) =>
        definition.type === "ImportSpecifier" &&
        parent?.type === "ImportDeclaration" &&
        parent.source.value === specifier &&
        (definition.imported.type === "Identifier"
          ? definition.imported.name
          : definition.imported.value) === name,
    );
  }

  return false;
}

function nativeFetchType(source: SourceCode, initial: ESTree.Node) {
  const pending = [initial];
  const seen = new Set<ESTree.Node>();

  while (pending.length > 0) {
    const node = pending.pop();

    if (!node || seen.has(node)) {
      continue;
    }

    seen.add(node);

    if (node.type === "TSTypeQuery") {
      const name = node.exprName;

      if (
        name.type === "Identifier" &&
        nativePropertyPath(source, name) === "fetch"
      ) {
        return true;
      }

      if (
        name.type === "TSQualifiedName" &&
        name.right.name === "fetch" &&
        globalObject(source, name.left)
      ) {
        return true;
      }
    }

    if (node.type === "TSTypeReference") {
      for (const definition of lexicalVariable(source, node.typeName)?.defs ??
        []) {
        if (definition.node.type === "TSTypeAliasDeclaration") {
          pending.push(definition.node.typeAnnotation);
        }
      }
    }
  }

  return false;
}

function knockConstructor(source: SourceCode, initial: ESTree.Node) {
  const specifier = "@knocklabs/node";
  const node = resolvedConstant(source, initial);

  if (cloudflareImport(source, node, "Knock", specifier)) {
    return true;
  }

  const reference = destructuredReference(source, node);

  if (reference) {
    return (
      ["default", "Knock"].includes(reference.property) &&
      namespaceImport(source, reference.object, specifier)
    );
  }

  if (node.type === "MemberExpression") {
    return (
      ["default", "Knock"].includes(propertyName(source, node) ?? "") &&
      namespaceImport(source, node.object, specifier)
    );
  }

  return (
    lexicalVariable(source, node)?.defs.some(
      ({ node: definition, parent }) =>
        definition.type === "ImportDefaultSpecifier" &&
        parent?.type === "ImportDeclaration" &&
        parent.source.value === specifier,
    ) ?? false
  );
}

type EffectiveOption = (
  source: SourceCode,
  initial: ESTree.Node,
  name: string,
  ancestors?: Set<ESTree.Node>,
) => ESTree.Node | null | false;

const effectiveOption: EffectiveOption = (
  source,
  initial,
  name,
  ancestors = new Set<ESTree.Node>(),
) => {
  const node = resolvedConstant(source, initial);

  if (node.type !== "ObjectExpression" || ancestors.has(node)) {
    return null;
  }

  const seen = new Set([...ancestors, node]);

  for (const property of node.properties.toReversed()) {
    if (property.type === "SpreadElement") {
      const value = effectiveOption(source, property.argument, name, seen);

      if (value !== false) {
        return value;
      }

      continue;
    }

    const key =
      !property.computed && property.key.type === "Identifier"
        ? property.key.name
        : literalKey(source, property.key);

    if (key === null) {
      return null;
    }

    if (key === name) {
      return property.value;
    }
  }

  return false;
};

function tauriMockImport(source: SourceCode, initial: ESTree.Node) {
  const specifier = "@tauri-apps/api/mocks";
  const node = resolvedConstant(source, initial);

  for (const name of tauriMockMethods) {
    if (cloudflareImport(source, node, name, specifier)) {
      return true;
    }
  }

  if (node.type === "MemberExpression") {
    return (
      tauriMockMethods.has(propertyName(source, node) ?? "") &&
      namespaceImport(source, node.object, specifier)
    );
  }

  const reference = destructuredReference(source, node);

  return (
    reference !== null &&
    tauriMockMethods.has(reference.property) &&
    namespaceImport(source, reference.object, specifier)
  );
}

function durableParameter(source: SourceCode, node: ESTree.Node) {
  if (node.type !== "Identifier") {
    return false;
  }

  for (
    let scope: Scope | null = source.getScope(node);
    scope !== null;
    scope = scope.upper
  ) {
    const variable = scope.set.get(node.name);

    if (!variable || variable.defs.length === 0) {
      continue;
    }

    return variable.defs.some((definition) => {
      const callback = definition.node;

      if (
        definition.type !== "Parameter" ||
        (callback.type !== "ArrowFunctionExpression" &&
          callback.type !== "FunctionExpression") ||
        !callback.params
          .slice(0, 2)
          .some(
            (parameter) =>
              parameter.type === "Identifier" && parameter.name === node.name,
          ) ||
        callback.parent.type !== "CallExpression"
      ) {
        return false;
      }

      const { callee, args } = invokedFunction(source, callback.parent);

      return (
        args[1] === callback &&
        cloudflareImport(
          source,
          callee,
          "runInDurableObject",
          "cloudflare:test",
        )
      );
    });
  }

  return false;
}

function playwrightType(
  source: SourceCode,
  node: ESTree.Node,
  names: string[],
) {
  return (
    lexicalVariable(source, node)?.identifiers.some((identifier) => {
      const annotation = identifier.typeAnnotation?.typeAnnotation;

      return (
        annotation?.type === "TSTypeReference" &&
        ["@playwright/test", "playwright", "playwright-core"].some(
          (specifier) =>
            names.some((name) =>
              cloudflareImport(source, annotation.typeName, name, specifier),
            ),
        )
      );
    }) ?? false
  );
}

function playwrightObject(source: SourceCode, initial: ESTree.Node) {
  if (
    playwrightType(source, initial, [
      "Page",
      "BrowserContext",
      "Browser",
      "BrowserType",
    ])
  ) {
    return true;
  }

  const pending = [initial];
  const seen = new Set<ESTree.Node>();

  while (pending.length > 0) {
    const current = pending.pop();

    if (!current) {
      continue;
    }

    const node = resolvedConstant(source, current);

    if (seen.has(node)) {
      continue;
    }

    seen.add(node);

    if (
      playwrightType(source, node, [
        "Page",
        "BrowserContext",
        "Browser",
        "BrowserType",
      ])
    ) {
      return true;
    }

    if (
      ["@playwright/test", "playwright", "playwright-core"].some((specifier) =>
        ["chromium", "firefox", "webkit"].some((name) =>
          cloudflareImport(source, node, name, specifier),
        ),
      )
    ) {
      return true;
    }

    if (node.type === "AwaitExpression") {
      pending.push(node.argument);
    } else if (node.type === "ConditionalExpression") {
      pending.push(node.consequent, node.alternate);
    } else if (node.type === "CallExpression") {
      const { callee } = invokedFunction(source, node);

      if (
        callee.type === "MemberExpression" &&
        [
          "launch",
          "launchPersistentContext",
          "connect",
          "connectOverCDP",
          "newContext",
          "newPage",
        ].includes(propertyName(source, callee) ?? "")
      ) {
        pending.push(callee.object);
      }
    }
  }

  return false;
}

function playwrightRoute(source: SourceCode, initial: ESTree.Node) {
  if (playwrightType(source, initial, ["Route"])) {
    return true;
  }

  const node = resolvedConstant(source, initial);
  const variable = lexicalVariable(source, node);

  return (
    variable?.defs.some((definition) => {
      const callback = definition.node;

      if (
        definition.type !== "Parameter" ||
        (callback.type !== "ArrowFunctionExpression" &&
          callback.type !== "FunctionExpression") ||
        callback.params[0]?.type !== "Identifier" ||
        lexicalVariable(source, callback.params[0]) !== variable ||
        callback.parent.type !== "CallExpression"
      ) {
        return false;
      }

      const { callee, args } = invokedFunction(source, callback.parent);

      return (
        args[1] === callback &&
        callee.type === "MemberExpression" &&
        propertyName(source, callee) === "route" &&
        playwrightObject(source, callee.object)
      );
    }) ?? false
  );
}

function staticRouteResponse(source: SourceCode, initial: ESTree.Node) {
  const pending = [{ node: initial, field: false }];
  const seenObjects = new Set<ESTree.Node>();
  const seenValues = new Set<ESTree.Node>();

  while (pending.length > 0) {
    const next = pending.pop();

    if (!next) {
      continue;
    }

    const node = resolvedConstant(source, next.node);
    const seen = next.field ? seenValues : seenObjects;

    if (seen.has(node)) {
      continue;
    }

    seen.add(node);

    if (node.type === "ConditionalExpression") {
      pending.push(
        { node: node.consequent, field: next.field },
        { node: node.alternate, field: next.field },
      );

      continue;
    }

    if (node.type === "LogicalExpression") {
      pending.push(
        { node: node.left, field: next.field },
        { node: node.right, field: next.field },
      );

      continue;
    }

    if (
      next.field &&
      [
        "Literal",
        "TemplateLiteral",
        "ObjectExpression",
        "ArrayExpression",
      ].includes(node.type)
    ) {
      return true;
    }

    if (node.type !== "ObjectExpression") {
      continue;
    }

    for (const property of node.properties) {
      if (property.type === "SpreadElement") {
        pending.push({ node: property.argument, field: false });

        continue;
      }

      const key =
        !property.computed && property.key.type === "Identifier"
          ? property.key.name
          : literalKey(source, property.key);

      if (["body", "json", "status", "contentType"].includes(key ?? "")) {
        pending.push({ node: property.value, field: true });
      }
    }
  }

  return false;
}

function workerBinding(source: SourceCode, initial: ESTree.Node) {
  let node = resolvedConstant(source, initial);
  const seen = new Set<ESTree.Node>();

  while (!seen.has(node)) {
    seen.add(node);

    if (
      cloudflareImport(source, node, "env") ||
      durableParameter(source, node)
    ) {
      return true;
    }

    const reference = destructuredReference(source, node);

    if (reference) {
      node = resolvedConstant(source, reference.object);

      continue;
    }

    if (node.type !== "MemberExpression") {
      return false;
    }

    node = resolvedConstant(source, node.object);
  }

  return false;
}

function containsFunction(source: SourceCode, initial: ESTree.Node) {
  const pending = [initial];
  const seen = new Set<ESTree.Node>();

  while (pending.length > 0) {
    const next = pending.pop();

    if (!next) {
      continue;
    }

    const node = resolvedConstant(source, next);

    if (seen.has(node)) {
      continue;
    }

    seen.add(node);

    if (
      node.type === "ArrowFunctionExpression" ||
      node.type === "FunctionExpression" ||
      node.type === "FunctionDeclaration"
    ) {
      return true;
    }

    if (node.type === "CallExpression") {
      const callee = resolvedConstant(source, node.callee);

      if (
        callee.type === "MemberExpression" &&
        propertyName(source, callee) === "bind"
      ) {
        const receiver = resolvedConstant(source, callee.object);

        if (receiver.type !== "ObjectExpression") {
          pending.push(receiver);
        }
      }
    }

    if (node.type === "ObjectExpression") {
      for (const property of node.properties) {
        pending.push(
          property.type === "SpreadElement"
            ? property.argument
            : property.value,
        );
      }
    }

    if (node.type === "ConditionalExpression") {
      pending.push(node.consequent, node.alternate);
    }

    if (node.type === "LogicalExpression") {
      pending.push(node.left, node.right);
    }

    if (node.type === "SequenceExpression") {
      const result = node.expressions.at(-1);

      if (result) {
        pending.push(result);
      }
    }
  }

  return false;
}

function localResults(source: SourceCode, initial: ESTree.Node) {
  const pending: {
    node: ESTree.Node;
    path: string[];
    ancestors: Set<ESTree.Node>;
  }[] = [{ node: initial, path: [], ancestors: new Set() }];

  const visited = new Map<ESTree.Node, Set<string>>();
  const results: ESTree.Node[] = [];

  while (pending.length > 0) {
    const next = pending.pop();

    if (!next) {
      continue;
    }

    const node = resolvedConstant(source, next.node);
    const key = JSON.stringify(next.path);
    const paths = visited.get(node) ?? new Set<string>();

    if (paths.has(key) || next.ancestors.has(node)) {
      continue;
    }

    paths.add(key);

    visited.set(node, paths);

    const push = (value: ESTree.Node, path = next.path) => {
      pending.push({
        node: value,
        path,
        ancestors: new Set([...next.ancestors, node]),
      });
    };

    const reference = destructuredReference(source, node);

    if (reference) {
      push(reference.object, [reference.property, ...next.path]);

      continue;
    }

    if (node.type === "CallExpression") {
      const { callee } = invokedFunction(source, node);

      if (
        callee.type === "FunctionDeclaration" ||
        callee.type === "FunctionExpression" ||
        callee.type === "ArrowFunctionExpression"
      ) {
        if (callee.body?.type === "BlockStatement") {
          for (const statement of callee.body.body) {
            if (statement.type === "ReturnStatement" && statement.argument) {
              push(statement.argument);
            }
          }
        } else if (callee.body) {
          push(callee.body);
        }

        continue;
      }
    }

    if (node.type === "MemberExpression") {
      const property = propertyName(source, node);

      if (property !== null) {
        push(node.object, [property, ...next.path]);
      }

      continue;
    }

    if (node.type === "ConditionalExpression") {
      push(node.consequent);

      push(node.alternate);

      continue;
    }

    if (node.type === "ObjectExpression" && next.path.length > 0) {
      const [property, ...rest] = next.path;

      for (const field of node.properties) {
        if (field.type === "SpreadElement") {
          push(field.argument);
        } else if (
          (!field.computed && field.key.type === "Identifier"
            ? field.key.name
            : literalKey(source, field.key)) === property
        ) {
          push(field.value, rest);
        }
      }

      continue;
    }

    const variable = lexicalVariable(source, node);

    for (const definition of variable?.defs ?? []) {
      const owner = definition.node;

      if (
        definition.type !== "Parameter" ||
        owner.type !== "FunctionDeclaration" ||
        !owner.id
      ) {
        continue;
      }

      const index = owner.params.findIndex(
        (parameter) => lexicalVariable(source, parameter) === variable,
      );

      for (const call of lexicalVariable(source, owner.id)?.references ?? []) {
        const { parent } = call.identifier;

        if (
          parent.type === "CallExpression" &&
          parent.callee === call.identifier
        ) {
          const argument = parent.arguments[index];

          if (argument && argument.type !== "SpreadElement") {
            push(argument);
          }
        }
      }
    }

    if (next.path.length === 0) {
      results.push(node);
    }
  }

  return results;
}

function honoReceiver(
  source: SourceCode,
  initial: ESTree.Node,
  filename: string,
) {
  const pending = [initial];
  const seen = new Set<ESTree.Node>();

  while (pending.length > 0) {
    const next = pending.pop();

    if (!next) {
      continue;
    }

    for (const node of localResults(source, next)) {
      if (seen.has(node)) {
        continue;
      }

      seen.add(node);

      if (
        node.type === "NewExpression" &&
        (cloudflareImport(source, node.callee, "Hono", "hono") ||
          cloudflareImport(
            source,
            node.callee,
            "OpenAPIHono",
            "@hono/zod-openapi",
          ))
      ) {
        return true;
      }

      if (node.type === "CallExpression") {
        const { callee } = invokedFunction(source, node);

        if (callee.type === "CallExpression") {
          pending.push(callee);
        } else if (
          callee.type === "MemberExpression" &&
          [
            "use",
            "route",
            "get",
            "post",
            "put",
            "patch",
            "delete",
            "all",
            "on",
            "basePath",
            "notFound",
            "onError",
          ].includes(propertyName(source, callee) ?? "")
        ) {
          pending.push(callee.object);
        }
      }

      if (
        /(?:^|\/)src\/workers\/[^/]+\/(?:tests?|__tests__)\//u.test(
          filename.replaceAll("\\", "/"),
        ) &&
        lexicalVariable(source, node)?.defs.some(
          ({ node: definition, parent }) =>
            definition.type === "ImportDefaultSpecifier" &&
            parent?.type === "ImportDeclaration" &&
            /^(?:\.\.\/)+src(?:\/index(?:\.[cm]?[jt]s)?)?$/u.test(
              parent.source.value,
            ),
        )
      ) {
        return true;
      }
    }
  }

  return false;
}

function handwrittenBindings(source: SourceCode, initial: ESTree.Node) {
  const pending = [initial];
  const seen = new Set<ESTree.Node>();
  const objects: ESTree.ObjectExpression[] = [];

  while (pending.length > 0) {
    const next = pending.pop();

    if (!next) {
      continue;
    }

    for (const node of localResults(source, next)) {
      if (seen.has(node) || node.type !== "ObjectExpression") {
        continue;
      }

      seen.add(node);

      for (const property of node.properties) {
        if (property.type === "SpreadElement") {
          pending.push(property.argument);

          continue;
        }

        const key =
          !property.computed && property.key.type === "Identifier"
            ? property.key.name
            : literalKey(source, property.key);

        if (
          key &&
          /^[A-Z][A-Z0-9_]*$/u.test(key) &&
          containsFunction(source, property.value)
        ) {
          objects.push(node);

          break;
        }
      }
    }
  }

  return objects;
}

function definesReplacementGlobal(
  source: SourceCode,
  initial: ESTree.Node | undefined,
  properties: ReadonlySet<string>,
) {
  const pending = initial ? [initial] : [];
  const visited = new Set<ESTree.Node>();

  while (pending.length > 0) {
    const next = pending.pop();
    const node = next ? resolvedConstant(source, next) : undefined;

    if (!node || visited.has(node)) {
      continue;
    }

    visited.add(node);

    if (node.type === "ConditionalExpression") {
      pending.push(node.consequent, node.alternate);
    }

    if (node.type === "LogicalExpression") {
      pending.push(node.left, node.right);
    }

    if (node.type === "SequenceExpression") {
      const result = node.expressions.at(-1);

      if (result) {
        pending.push(result);
      }
    }

    if (node.type !== "ObjectExpression") {
      continue;
    }

    for (const property of node.properties) {
      if (property.type === "SpreadElement") {
        pending.push(property.argument);

        continue;
      }

      const key =
        !property.computed && property.key.type === "Identifier"
          ? property.key.name
          : literalKey(source, property.key);

      if (key !== null && properties.has(key)) {
        return true;
      }
    }
  }

  return false;
}

function observationOptions(node: ESTree.Node | undefined) {
  return (
    node?.type === "ObjectExpression" &&
    node.properties.length === 1 &&
    node.properties.some(
      (property) =>
        property.type === "Property" &&
        !property.computed &&
        ((property.key.type === "Identifier" && property.key.name === "spy") ||
          (property.key.type === "Literal" && property.key.value === "spy")) &&
        property.value.type === "Literal" &&
        property.value.value === true,
    )
  );
}

function invokedFunction(source: SourceCode, node: ESTree.CallExpression) {
  let target: ESTree.Node = resolvedConstant(source, node.callee);
  let args: (ESTree.Node | null)[] = [...node.arguments];
  const visited = new Set<ESTree.Node>();

  while (!visited.has(target)) {
    visited.add(target);

    if (target.type === "CallExpression") {
      const bound = resolvedConstant(source, target.callee);

      if (
        bound.type !== "MemberExpression" ||
        propertyName(source, bound) !== "bind"
      ) {
        break;
      }

      args.unshift(...target.arguments.slice(1));

      target = resolvedConstant(source, bound.object);

      continue;
    }

    if (nativePropertyPath(source, target) === "Reflect.apply") {
      const [fn, , list] = args;

      if (!fn) {
        break;
      }

      const values = list ? resolvedConstant(source, list) : null;

      args = values?.type === "ArrayExpression" ? [...values.elements] : [];

      target = resolvedConstant(source, fn);

      continue;
    }

    if (target.type !== "MemberExpression") {
      break;
    }

    const method = propertyName(source, target);

    if (method === "call") {
      args = args.slice(1);
    } else if (method === "apply") {
      const [, list] = args;
      const values = list ? resolvedConstant(source, list) : null;

      args = values?.type === "ArrayExpression" ? [...values.elements] : [];
    } else {
      break;
    }

    target = resolvedConstant(source, target.object);
  }

  return { callee: target, args };
}

function mswResponseConstructor(source: SourceCode, initial: ESTree.Node) {
  const node = resolvedConstant(source, initial);

  return (
    cloudflareImport(source, node, "HttpResponse", "msw") ||
    (node.type === "MemberExpression" &&
      propertyName(source, node) === "HttpResponse" &&
      namespaceImport(source, node.object, "msw"))
  );
}

function rawResponse(
  source: SourceCode,
  initial: ESTree.Node,
  includeMsw = false,
) {
  const pending = [initial];
  const visited = new Set<ESTree.Node>();

  while (pending.length > 0) {
    const next = pending.pop();

    if (!next) {
      continue;
    }

    const node = resolvedConstant(source, next);

    if (visited.has(node)) {
      continue;
    }

    visited.add(node);

    switch (node.type) {
      case "NewExpression": {
        if (
          nativePropertyPath(source, node.callee) === "Response" ||
          (includeMsw && mswResponseConstructor(source, node.callee))
        ) {
          return true;
        }

        break;
      }
      case "CallExpression": {
        const { callee, args } = invokedFunction(source, node);
        const path = nativePropertyPath(source, callee);

        if (path === "Promise.resolve" && args[0]) {
          pending.push(args[0]);
        }

        if (
          includeMsw &&
          callee.type === "MemberExpression" &&
          [
            "json",
            "text",
            "html",
            "xml",
            "arrayBuffer",
            "formData",
            "error",
            "redirect",
            "bytes",
          ].includes(propertyName(source, callee) ?? "") &&
          mswResponseConstructor(source, callee.object)
        ) {
          return true;
        }

        if (
          path &&
          ["Response.json", "Response.redirect", "Response.error"].includes(
            path,
          )
        ) {
          return true;
        }

        if (
          (callee.type === "FunctionDeclaration" ||
            callee.type === "FunctionExpression" ||
            callee.type === "ArrowFunctionExpression") &&
          callee.body
        ) {
          pending.push(callee.body);
        }

        break;
      }
      case "FunctionDeclaration":
      case "FunctionExpression":
      case "ArrowFunctionExpression": {
        if (node.body) {
          pending.push(node.body);
        }

        break;
      }
      case "BlockStatement": {
        pending.push(
          ...node.body.filter(
            (statement) => statement.type !== "FunctionDeclaration",
          ),
        );

        break;
      }
      case "ReturnStatement": {
        if (node.argument) {
          pending.push(node.argument);
        }

        break;
      }
      case "AwaitExpression": {
        pending.push(node.argument);

        break;
      }
      case "IfStatement": {
        pending.push(node.consequent);

        if (node.alternate) {
          pending.push(node.alternate);
        }

        break;
      }
      case "ConditionalExpression": {
        pending.push(node.consequent, node.alternate);

        break;
      }
      case "LogicalExpression": {
        pending.push(node.left, node.right);

        break;
      }
      case "SequenceExpression": {
        const result = node.expressions.at(-1);

        if (result) {
          pending.push(result);
        }

        break;
      }
      case "SwitchStatement": {
        pending.push(...node.cases.flatMap((branch) => branch.consequent));

        break;
      }
      case "TryStatement": {
        pending.push(node.block);

        if (node.handler) {
          pending.push(node.handler.body);
        }

        if (node.finalizer) {
          pending.push(node.finalizer);
        }

        break;
      }
      default: {
        break;
      }
    }
  }

  return false;
}

function rawServiceBindings(source: SourceCode, initial: ESTree.Node) {
  const pending = [initial];
  const visited = new Set<ESTree.Node>();

  while (pending.length > 0) {
    const next = pending.pop();

    if (!next) {
      continue;
    }

    const node = resolvedConstant(source, next);

    if (visited.has(node) || node.type !== "ObjectExpression") {
      continue;
    }

    visited.add(node);

    for (const property of node.properties) {
      if (property.type === "SpreadElement") {
        pending.push(property.argument);
      } else if (rawResponse(source, property.value)) {
        return true;
      }
    }
  }

  return false;
}

export const noTestDoubles = defineRule({
  meta: {
    type: "problem",
    schema: [],
    docs: {
      description:
        "Keep real implementations in tests; intercept network requests with MSW and allow observation-only spies.",
    },
    messages: {
      replacement:
        "Do not replace test dependency behavior. Use the real implementation and MSW for network responses; spies must only observe.",
    },
  },
  create(context) {
    const source = context.sourceCode;

    const testCode =
      /(?:^|\/)(?:__tests__|tests?|testing|test-utils)(?:\/|$)|(?:^|[/.])(?:test|spec|fixture|mock|setup|commands)(?:\.[^/]*)?$/u.test(
        context.filename.replaceAll("\\", "/"),
      ) ||
      source.ast.body.some(
        (node) =>
          node.type === "ImportDeclaration" &&
          /^(?:vitest(?:\/|$)|@jest\/globals$|node:test$)/u.test(
            node.source.value,
          ),
      );

    const vitestConfig =
      /(?:^|\/)vitest(?:\.[\w-]+)*\.config\.[cm]?[jt]s$/u.test(
        context.filename.replaceAll("\\", "/"),
      );

    const reportedBindings = new Set<ESTree.Node>();

    const savedMembers: ESTree.VariableDeclarator[] = [];
    const assignments: ESTree.AssignmentExpression[] = [];

    return {
      VariableDeclarator(node) {
        if (
          testCode &&
          node.id.type === "Identifier" &&
          node.init?.type === "MemberExpression"
        ) {
          savedMembers.push(node);
        }

        if (testCode && node.id.type === "Identifier" && node.init) {
          const annotation = node.id.typeAnnotation?.typeAnnotation;
          const implementation = resolvedConstant(source, node.init);

          if (
            annotation &&
            nativeFetchType(source, annotation) &&
            rawResponse(source, implementation, true) &&
            !reportedBindings.has(implementation)
          ) {
            reportedBindings.add(implementation);

            context.report({ node: node.init, messageId: "replacement" });
          }
        }
      },
      "Program:exit"() {
        for (const assignment of assignments) {
          const replacement = resolvedConstant(source, assignment.right);

          if (
            assignment.left.type !== "MemberExpression" ||
            (replacement.type !== "ArrowFunctionExpression" &&
              replacement.type !== "FunctionExpression" &&
              replacement.type !== "FunctionDeclaration")
          ) {
            continue;
          }

          const property = propertyName(source, assignment.left);
          const { object } = assignment.left;

          if (
            workerBinding(source, assignment.left) ||
            protectedProperties(source, object)?.has(property ?? "") ||
            (property?.startsWith("on") &&
              (globalObject(source, object) ||
                nativePropertyPath(source, object) === "document"))
          ) {
            continue;
          }

          const saved = savedMembers.some((declaration) => {
            if (
              declaration.id.type !== "Identifier" ||
              !declaration.init ||
              declaration.range[0] >= assignment.range[0] ||
              !sameMember(source, declaration.init, assignment.left)
            ) {
              return false;
            }

            const variable = lexicalVariable(source, declaration.id);

            return (
              variable !== null &&
              initializedOnce(variable) &&
              !delegatesSavedMember(source, replacement, variable) &&
              assignments.some(
                (restore) =>
                  restore.range[0] > assignment.range[0] &&
                  restore.right.type === "Identifier" &&
                  lexicalVariable(source, restore.right) === variable &&
                  sameMember(source, restore.left, assignment.left),
              )
            );
          });

          if (saved) {
            context.report({ node: assignment, messageId: "replacement" });
          }
        }
      },
      NewExpression(node) {
        if (!testCode || !knockConstructor(source, node.callee)) {
          return;
        }

        const [options] = node.arguments;

        if (!options || options.type === "SpreadElement") {
          return;
        }

        for (const value of localResults(source, options)) {
          const transport = effectiveOption(source, value, "fetch");

          if (
            transport !== null &&
            transport !== false &&
            rawResponse(source, transport, true)
          ) {
            const implementation = resolvedConstant(source, transport);

            if (!reportedBindings.has(implementation)) {
              reportedBindings.add(implementation);

              context.report({ node: transport, messageId: "replacement" });
            }

            break;
          }
        }
      },
      ObjectExpression(node) {
        if (
          node.parent.type === "CallExpression" &&
          cloudflareImport(
            source,
            invokedFunction(source, node.parent).callee,
            "withEnv",
          )
        ) {
          return;
        }

        if (
          testCode &&
          node.properties.some(
            (property) =>
              property.type === "SpreadElement" &&
              workerBinding(source, property.argument),
          ) &&
          containsFunction(source, node) &&
          !reportedBindings.has(node)
        ) {
          reportedBindings.add(node);

          context.report({ node, messageId: "replacement" });
        }
      },
      Property(node) {
        if (!vitestConfig) {
          return;
        }

        const key =
          !node.computed && node.key.type === "Identifier"
            ? node.key.name
            : literalKey(source, node.key);

        if (
          (key === "outboundService" && rawResponse(source, node.value)) ||
          (key === "serviceBindings" && rawServiceBindings(source, node.value))
        ) {
          context.report({ node, messageId: "replacement" });
        }
      },
      CallExpression(node) {
        const { callee, args } = invokedFunction(source, node);

        if (
          testCode &&
          callee.type === "MemberExpression" &&
          propertyName(source, callee) === "request" &&
          args[2] &&
          honoReceiver(source, callee.object, context.filename)
        ) {
          for (const binding of handwrittenBindings(source, args[2])) {
            if (!reportedBindings.has(binding)) {
              reportedBindings.add(binding);

              context.report({ node: binding, messageId: "replacement" });
            }
          }
        }

        if (
          testCode &&
          callee.type === "MemberExpression" &&
          propertyName(source, callee) === "fulfill" &&
          playwrightRoute(source, callee.object) &&
          args[0] &&
          staticRouteResponse(source, args[0])
        ) {
          context.report({ node, messageId: "replacement" });
        }

        const replacement = replacementMethod(source, callee);

        if (tauriMockImport(source, callee)) {
          context.report({ node, messageId: "replacement" });
        }

        if (
          replacement !== null &&
          (replacements.has(replacement) ||
            (frameworkReplacements.has(replacement) &&
              !(
                ["mock", "doMock", "mockObject"].includes(replacement) &&
                args.length === 2 &&
                !jestFramework(source, callee) &&
                observationOptions(args[1] ?? undefined)
              )) ||
            (replacement === "fn" &&
              args[0] !== null &&
              args[0] !== undefined &&
              !(
                args[0].type === "Identifier" &&
                args[0].name === "undefined" &&
                unshadowed(source, args[0])
              )))
        ) {
          context.report({ node, messageId: "replacement" });
        }

        const mutation = nativePropertyPath(source, callee);

        if (testCode) {
          const [target] = args;
          let candidates: typeof args = [];

          if (cloudflareImport(source, callee, "withEnv")) {
            candidates = args.slice(0, 1);
          } else if (target && workerBinding(source, target)) {
            switch (mutation) {
              case "Object.assign": {
                candidates = args.slice(1);

                break;
              }
              case "Object.defineProperty":
              case "Reflect.defineProperty":
              case "Reflect.set": {
                candidates = args.slice(2, 3);

                break;
              }
              case "Object.defineProperties": {
                candidates = args.slice(1, 2);

                break;
              }
              default: {
                break;
              }
            }
          }

          if (
            candidates.some((value) => value && containsFunction(source, value))
          ) {
            context.report({ node, messageId: "replacement" });
          }
        }

        if (
          testCode &&
          mutation !== null &&
          args[0] !== null &&
          args[0] !== undefined
        ) {
          const properties = protectedProperties(source, args[0]);

          if (!properties) {
            return;
          }

          const [, argument] = args;

          if (
            ([
              "Object.defineProperty",
              "Reflect.defineProperty",
              "Reflect.set",
              "Reflect.deleteProperty",
            ].includes(mutation) &&
              properties.has(
                literalKey(source, argument ?? undefined) ?? "",
              )) ||
            (mutation === "Object.defineProperties" &&
              definesReplacementGlobal(
                source,
                argument ?? undefined,
                properties,
              )) ||
            (mutation === "Object.assign" &&
              args
                .slice(1)
                .some((value) =>
                  definesReplacementGlobal(
                    source,
                    value ?? undefined,
                    properties,
                  ),
                ))
          ) {
            context.report({ node, messageId: "replacement" });
          }
        }
      },
      UnaryExpression(node) {
        if (
          testCode &&
          node.operator === "delete" &&
          node.argument.type === "MemberExpression" &&
          protectedProperties(source, node.argument.object)?.has(
            String(propertyName(source, node.argument)),
          )
        ) {
          context.report({ node, messageId: "replacement" });
        }
      },
      AssignmentExpression(node) {
        if (!testCode) {
          return;
        }

        if (node.operator === "=") {
          assignments.push(node);
        }

        const target = node.left;

        if (
          workerBinding(source, target) &&
          containsFunction(source, node.right)
        ) {
          context.report({ node, messageId: "replacement" });
        }

        if (
          (target.type === "Identifier" &&
            replacementGlobals.has(target.name) &&
            unshadowed(source, target)) ||
          (target.type === "MemberExpression" &&
            protectedProperties(source, target.object)?.has(
              String(propertyName(source, target)),
            ))
        ) {
          context.report({ node, messageId: "replacement" });
        }
      },
    };
  },
});
