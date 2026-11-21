import { basename, dirname, relative, sep } from "node:path";
import { defineRule } from "@oxlint/plugins";

import { packageDirectory } from "../lib/test-owner.ts";

const extension = String.raw`\.[cm]?[jt]sx?$`;

const misnamedTest = new RegExp(
  String.raw`\.(?:spec|specs|tests)${extension}`,
  "u",
);

const fixtureWord = new RegExp(
  String.raw`(?:^|[-_.])fixtures?${extension}`,
  "u",
);

const namedFixture = new RegExp(String.raw`.\.fixture${extension}`, "u");

const misnamedHelper = new RegExp(
  String.raw`\.(?:test-helpers?|test-util|testutils?|test-utilities|helpers?|mocks?|stubs?|harness)${extension}`,
  "u",
);

const testDirectories = new Set(["tests", "__tests__"]);

function nameKind(name: string) {
  if (misnamedTest.test(name)) {
    return "test";
  }

  if (fixtureWord.test(name) && !namedFixture.test(name)) {
    return "fixture";
  }

  return misnamedHelper.test(name) ? "helper" : undefined;
}

export const testFileNames = defineRule({
  meta: {
    type: "suggestion",
    schema: [],
    docs: {
      description:
        "Name tests, fixtures and test helpers with the repository's suffixes.",
    },
    messages: {
      test: "Name test files <subject>.test.ts, adding a runtime infix such as .browser.test.tsx when a Vitest project needs one.",
      fixture: "Name test data <subject>.fixture.ts.",
      helper: "Name test helpers, harnesses and mocks <subject>.test-utils.ts.",
      directory: "Put tests in a test directory, not {{directory}}.",
    },
  },
  create(context) {
    return {
      Program(node) {
        const filename = context.physicalFilename;
        const directory = dirname(filename);
        const messageId = nameKind(basename(filename));

        const misplaced = relative(packageDirectory(directory), directory)
          .split(sep)
          .find((part) => testDirectories.has(part));

        if (messageId) {
          context.report({ node, messageId });
        }

        if (misplaced) {
          context.report({
            node,
            messageId: "directory",
            data: { directory: misplaced },
          });
        }
      },
    };
  },
});
