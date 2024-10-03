#!/usr/bin/env bash

temp_dir=$(mktemp -d)
trap "rm -r $temp_dir" EXIT

echo "bctf{fake_flag}" > "$temp_dir/flag.txt"

cp Dockerfile "$temp_dir"
cp app.py "$temp_dir"
cp requirements.txt "$temp_dir"
cp -r templates "$temp_dir"
cp -r static "$temp_dir"

out=$(pwd)
cd "$temp_dir"
zip -r "export.zip" .
mv "export.zip" "$out"/export.zip
