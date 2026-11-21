import { definePlugin } from "@oxlint/plugins";

import { noExplicitReturnTypes } from "../rules/no-explicit-return-types.ts";

const plugin = definePlugin({
  meta: { name: "landmines-types" },
  rules: {
    "no-explicit-return-types": noExplicitReturnTypes,
  },
});

// oxlint-disable-next-line import/no-default-export
export default plugin;
