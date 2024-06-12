find . -type d -exec bash -c 'mkdir -p ../LIEF-0.14.1-Darwin/{}' \;
find . -type f -exec bash -c 'if [[ $(lipo -info {} 2>&1) == *"fatal error"* ]]; then cp {} ../LIEF-0.14.1-Darwin/{}; fi ' \;
find . -type f -exec bash -c 'if [[ ! $(lipo -info {} 2>&1) == *"fatal error"* ]]; then lipo -create -output ../LIEF-0.14.1-Darwin/{} {} ../LIEF-0.14.1-Darwin-arm64/{}; fi ' \;