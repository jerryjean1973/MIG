import { build } from "esbuild";
import { build as viteBuild } from "vite";
import { mkdir, writeFile, lstat } from "node:fs/promises";
import { resolve } from "node:path";
import { createRequire } from "node:module";

const root = resolve(".");
const require = createRequire(resolve(root, "package.json"));
const pkg = require("./package.json");
for (const name of Object.keys({ ...pkg.dependencies, ...pkg.devDependencies })) {
  // Packages must be installed in this checkout, not inherited from the
  // development monorepo. pnpm's local symlinks are expected.
  if (!await lstat(resolve(root, "node_modules", name)).catch(() => null)) {
    throw Error("MIG_DEPENDENCY_LOOKUP_INVALID:" + name);
  }
}
await mkdir("dist", { recursive: true });
const result = await build({
  absWorkingDir: root, entryPoints: ["server/index.ts"], outfile: "dist/server.mjs",
  bundle: true, platform: "node", format: "esm", target: "node22",
  packages: "external", metafile: true,
});
const forbidden = /(?:^|\/)(?:server\/bripe\/|shared\/breaking-point-engine|shared\/bripe\/|shared\/ripple\/|server\/ripple\/|client\/src\/features\/|product-distribution\/)/;
for (const input of Object.keys(result.metafile.inputs)) {
  if (input.startsWith("../") || forbidden.test(input)) throw Error("MIG_BUILD_SCOPE_VIOLATION:" + input);
}
await writeFile("dist/backend-inputs.json", JSON.stringify(Object.keys(result.metafile.inputs), null, 2));
await viteBuild();
