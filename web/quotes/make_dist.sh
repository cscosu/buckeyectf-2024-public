#!/usr/bin/env bash

set -x

temp_dir=$(mktemp -d)
trap "rm -r $temp_dir" EXIT

cp app.js "$temp_dir"
cp package.json "$temp_dir"
cp pnpm-lock.yaml "$temp_dir"
cp Dockerfile "$temp_dir"
cp .gitignore "$temp_dir"
cp README.dist.md "$temp_dir"/README.md
cp quotes.dist "$temp_dir"/quotes

out=$(pwd)
cd "$temp_dir"
zip -r "export.zip" .
mv "export.zip" "$out"/export.zip
