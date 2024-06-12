find . -type d -exec bash -c 'mkdir -p ../clang-llvm-14.0.6/{}' \;
find . -type f -exec bash -c 'if [[ $(lipo -info {} 2>&1) == *"fatal error"* ]]; then cp {} ../clang-llvm-14.0.6/{}; fi ' \;
find . -type f -exec bash -c 'if [[ ! $(lipo -info {} 2>&1) == *"fatal error"* ]]; then lipo -create -output ../clang-llvm-14.0.6/{} {} ../clang-llvm-14.0.6-arm64/{}; fi ' \;