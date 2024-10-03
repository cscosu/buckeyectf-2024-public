#!/usr/bin/env bash

set -x

temp_dir=$(mktemp -d)
trap "rm -r $temp_dir" EXIT

cp README.dist.md "$temp_dir"/README.md
cp Makefile "$temp_dir"
cp go.sum "$temp_dir"
cp go.mod "$temp_dir"
cp Dockerfile "$temp_dir"
cp .gitignore "$temp_dir"
cp .air.toml "$temp_dir"
cp -r cmd "$temp_dir"
cp -r internal "$temp_dir"
mkdir -p "$temp_dir"/frontend
cp -r frontend/src "$temp_dir"/frontend/
cp -r frontend/static "$temp_dir"/frontend/
cp frontend/.gitignore "$temp_dir"/frontend/
cp frontend/.npmrc "$temp_dir"/frontend/
cp frontend/.prettierignore "$temp_dir"/frontend/
cp frontend/.prettierrc "$temp_dir"/frontend/
cp frontend/eslint.config.js "$temp_dir"/frontend/
cp frontend/package.json "$temp_dir"/frontend/
cp frontend/pnpm-lock.yaml "$temp_dir"/frontend/
cp frontend/postcss.config.js "$temp_dir"/frontend/
cp frontend/svelte.config.js "$temp_dir"/frontend/
cp frontend/tailwind.config.js "$temp_dir"/frontend/
cp frontend/tsconfig.json "$temp_dir"/frontend/
cp frontend/vite.config.ts "$temp_dir"/frontend/

out=$(pwd)
cd "$temp_dir"
zip -r "export.zip" .
mv "export.zip" "$out"/export.zip
