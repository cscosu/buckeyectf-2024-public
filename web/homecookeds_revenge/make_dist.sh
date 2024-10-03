#!/usr/bin/env bash

temp_dir=$(mktemp -d)
trap "rm -r $temp_dir" EXIT

cp -r homecooked "$temp_dir"
cp -r static "$temp_dir"
cp -r templates "$temp_dir"
cp chef.py Dockerfile jail.cfg main.py requirements.txt run.sh "$temp_dir"

out=$(pwd)
cd "$temp_dir"
zip -r "export.zip" .
mv "export.zip" "$out"/export.zip
