#!/usr/bin/env zsh
set -ex

export MACOSX_DEPLOYMENT_TARGET=10.13
python3 ./bindings/python/setup.py --ninja --osx-arch='x86_64;arm64' \
                  --lief-dir=$GITHUB_WORKSPACE/third-party/LIEF-0.14.1-Darwin/share/LIEF/cmake \
                  --llvm-dir=$GITHUB_WORKSPACE/third-party/LLVM-14.0.6-Darwin/lib/cmake/llvm \
                  build bdist_wheel --skip-build

