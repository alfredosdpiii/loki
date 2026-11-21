import { definePlugin } from "@oxlint/plugins";

import { noFixedSleep } from "../rules/no-fixed-sleep.ts";
import { noFlakeMasking } from "../rules/no-flake-masking.ts";
import { noTestDoubles } from "../rules/no-test-doubles.ts";
import { noUnsignaledPoll } from "../rules/no-unsignaled-poll.ts";
import { strictMsw } from "../rules/strict-msw.ts";

const plugin = definePlugin({
  meta: { name: "landmines-testing" },
  rules: {
    "no-fixed-sleep": noFixedSleep,
    "no-flake-masking": noFlakeMasking,
    "no-test-doubles": noTestDoubles,
    "no-unsignaled-poll": noUnsignaledPoll,
    "strict-msw": strictMsw,
  },
});

// oxlint-disable-next-line import/no-default-export
export default plugin;
