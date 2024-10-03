#!/usr/bin/env bash

set -x

temp_dir=$(mktemp -d)
trap "rm -r $temp_dir" EXIT

cp -r dist "$temp_dir"

out=$(pwd)
cd "$temp_dir"
zip -r "export.zip" .
mv "export.zip" "$out"/export.zip
