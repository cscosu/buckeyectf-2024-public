#!/usr/bin/env bash
set -ex

temp_dir=$(mktemp -d)
trap "rm -rf $temp_dir" EXIT
cp -r Dockerfile.dist app.dist.py docker-compose.yml flag.dist.txt requirements.txt templates "$temp_dir"
pushd "$temp_dir"
mv flag.dist.txt flag.txt
mv app.dist.py app.py
mv Dockerfile.dist Dockerfile
zip -r export.zip *
popd
cp -r "$temp_dir/export.zip" .
