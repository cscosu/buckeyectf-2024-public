#!/usr/bin/env bash
set -ex

temp_dir=$(mktemp -d)
trap "rm -rf $temp_dir" EXIT
cp Dockerfile.dist app.py flag.txt index.html dotgitignore "$temp_dir"
pushd "$temp_dir"
mv Dockerfile.dist Dockerfile
mv dotgitignore .gitignore
git init
git config user.name "jm8"
git config user.email "jm8@pwnoh.io"
git add index.html
git commit -m "Initial commit (add index.html)"
git add -f app.py Dockerfile flag.txt 
git commit -m "Add app.py and Dockerfile"
git rm --cached flag.txt
git add .gitignore
git commit -m "Accidentally commited flag :facepalm:"
git reset --soft HEAD~~
git commit -m "Add app.py and Dockerfile but NOT flag"
echo this is an empty folder but i want it in git > .git/branches/ad2ebd399b0023ed35f2163dbfb98de703a22cba5ce6428e517d2a0a8deac
echo this is an empty folder but i want it in git > .git/refs/tags/8ac9e9c60867deee0a947b035e24e6e1a37f01aeee2c97cb83e257e700418
popd
rm -rf dotgit
cp -r "$temp_dir/.git" dotgit
