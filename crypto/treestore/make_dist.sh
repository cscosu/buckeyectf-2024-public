#!/usr/bin/env bash
set -ex

rm -rf treestore export.zip dist
mkdir dist

cp Dockerfile docker-compose.yml main.py make_flag.py ter-x32b.pbm ter-x32b.pil tree_store.py dist/
sed -i 's/bctf{.*}/bctf{__________________}/g' dist/make_flag.py

mv dist/ treestore/
zip -r export.zip treestore
rm -rf treestore
