# landmines

Vendored from [interfere-inc/landmines](https://github.com/interfere-inc/landmines) (MIT License, v0.1.1).

External runtime dependencies (`zod`, `@babel/parser`, `@babel/types`, `oxc-resolver`) were replaced with plain TypeScript option validation and Node built-in (`node:fs`, `node:path`) relative resolution so all four plugins (`landmines-testing`, `landmines-style`, `landmines-structure`, `landmines-types`) run under Oxlint with only `@oxlint/plugins` installed.
