#!/bin/sh

git submodule update --init --recursive lib/miracl-core
(cd lib/miracl-core/rust && git reset --hard && git clean -dfx . && git apply ../../../miracl-sign.patch && python3 config64.py 31 39)
