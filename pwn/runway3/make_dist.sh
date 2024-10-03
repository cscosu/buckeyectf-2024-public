#!/usr/bin/env bash

set -x

temp_dir=$(mktemp -d)
trap "rm -r $temp_dir" EXIT

cp runway3.c "$temp_dir"
cp runway3 "$temp_dir"
cp Makefile "$temp_dir"
cp Dockerfile "$temp_dir"
cp docker-compose.yaml "$temp_dir"
cp flag.dist.txt "$temp_dir/flag.txt"

out=$(pwd)
cd "$temp_dir"
zip -r "export.zip" .
mv "export.zip" "$out"/export.zip