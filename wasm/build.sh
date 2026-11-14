#!/bin/sh
# Build the npm package chaumian-sessions into wasm/pkg.
set -e
cd "$(dirname "$0")"
rm -rf pkg
wasm-pack build --target web --release --out-dir pkg --out-name chaumian_sessions_wasm
cp js/index.js pkg/
cp ../README.md ../LICENSE-MIT ../LICENSE-APACHE pkg/
node -e '
const fs = require("fs"), p = JSON.parse(fs.readFileSync("pkg/package.json"));
Object.assign(p, { name: "chaumian-sessions", main: "index.js", module: "index.js", type: "module",
  license: "MIT OR Apache-2.0", homepage: "https://github.com/Obscurify-ai/chaumian-sessions" });
p.files = ["index.js", "chaumian_sessions_wasm.js", "chaumian_sessions_wasm_bg.wasm", "chaumian_sessions_wasm.d.ts", "chaumian_sessions_wasm_bg.wasm.d.ts", "README.md", "LICENSE-MIT", "LICENSE-APACHE"];
delete p.types;
fs.writeFileSync("pkg/package.json", JSON.stringify(p, null, 2) + "\n");'
