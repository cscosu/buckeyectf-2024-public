#!/usr/bin/env bash

set -x

temp_dir=$(mktemp -d)
trap "rm -r $temp_dir" EXIT

cp text-adventure.jar "$temp_dir"
cp Dockerfile "$temp_dir"
cp docker-compose.yaml "$temp_dir"
cp flag.dist "$temp_dir/flag"

out=$(pwd)
cd "$temp_dir"
zip -r "export.zip" .
mv "export.zip" "$out"/export.zip