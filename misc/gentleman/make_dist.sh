#!/usr/bin/env bash

set -x

temp_dir=$(mktemp -d)
trap "rm -r $temp_dir" EXIT

cp -r typemonkey-app "$temp_dir"
cp EMAIL.txt "$temp_dir"
cp flag.dist.txt "$temp_dir"
cp Dockerfile "$temp_dir"
cp docker-compose.yaml "$temp_dir"

out=$(pwd)
cd "$temp_dir"
zip -r "export.zip" .
mv "export.zip" "$out"/export.zip
