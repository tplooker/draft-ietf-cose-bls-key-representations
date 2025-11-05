#!/bin/sh

# Exit on error
set -e

git submodule update --init --recursive lib/miracl-core
if [[ -d lib/mcore ]]; then git -C lib/miracl-core worktree remove --force --force ../mcore ; fi
git -C lib/miracl-core worktree add ../mcore

cd lib/mcore/rust
git apply ../../../miracl-sign.patch
python3 config64.py 31 39
