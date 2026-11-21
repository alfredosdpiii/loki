import { definePlugin } from "@oxlint/plugins";

import { noComments } from "../rules/no-comments.ts";

const plugin = definePlugin({
  meta: { name: "landmines-style" },
  rules: {
    "no-comments": noComments,
  },
});

// oxlint-disable-next-line import/no-default-export
export default plugin;
