#!/bin/sh
# Build the npm package unlinkable-inference into wasm/pkg.
set -e
cd "$(dirname "$0")"
rm -rf pkg
wasm-pack build --target web --release --out-dir pkg --out-name unlinkable_inference_wasm
cp js/index.js pkg/
cp ../README.md ../LICENSE-MIT ../LICENSE-APACHE pkg/
node -e '
const fs = require("fs"), p = JSON.parse(fs.readFileSync("pkg/package.json"));
Object.assign(p, { name: "unlinkable-inference", main: "index.js", module: "index.js", type: "module",
  license: "MIT OR Apache-2.0", homepage: "https://github.com/Obscurify-ai/unlinkable-inference" });
p.files = ["index.js", "unlinkable_inference_wasm.js", "unlinkable_inference_wasm_bg.wasm", "unlinkable_inference_wasm.d.ts", "unlinkable_inference_wasm_bg.wasm.d.ts", "README.md", "LICENSE-MIT", "LICENSE-APACHE"];
delete p.types;
fs.writeFileSync("pkg/package.json", JSON.stringify(p, null, 2) + "\n");'
