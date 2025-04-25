#!/bin/bash
#
function validateParams() {
  echo "========================= Checking parameters ========================="
  [[ -z $INPUT_BUGSPLAT_SYMBOL_URL ]] && echo "Bugsplat symbol url is required" && exit 1 || echo "Bugsplat symbol url pŕesent"
}

function build() {
  echo "========================= Building pktvisor ========================="
  cp -rf /github/workspace/.git/ /pktvisor-src/.git/
  cp -rf /github/workspace/src/ /pktvisor-src/src/
  cp -rf /github/workspace/cmd/ /pktvisor-src/cmd/
  cp -rf /github/workspace/3rd/ /pktvisor-src/3rd/
  cp -rf /github/workspace/libs/ /pktvisor-src/libs/
  cp -rf /github/workspace/docker/ /pktvisor-src/docker/
  cp -rf /github/workspace/build/ /pktvisor-src/build/
  cp -rf /github/workspace/golang/ /pktvisor-src/golang/
  cp -rf /github/workspace/integration_tests/ /pktvisor-src/integration_tests/
  cp -rf /github/workspace/cmake/ /pktvisor-src/cmake/
  cp -rf /github/workspace/CMakeLists.txt /pktvisor-src/
  cp -rf /github/workspace/conanfile.py /pktvisor-src/
  cp -rf /github/workspace/.conanrc /pktvisor-src/
  cd /pktvisor-src/
  conan profile detect -f
  cd /pktvisor-src/build/
  if [ "$INPUT_ARCH" == "amd64" ]; then
    PKG_CONFIG_PATH=/local/lib/pkgconfig cmake .. -DCMAKE_BUILD_TYPE=$INPUT_BUILD_TYPE \
     -DCMAKE_PROJECT_TOP_LEVEL_INCLUDES=./cmake/conan_provider.cmake -DASAN=$INPUT_ASAN
  elif [ "$INPUT_ARCH" == "arm64" ]; then
    echo "[settings]
    os=Linux
    arch=armv8
    compiler=gcc
    compiler.version=13
    compiler.cppstd=17
    compiler.libcxx=libstdc++11
    build_type=$INPUT_BUILD_TYPE
    [buildenv]
    CC=/usr/bin/aarch64-linux-gnu-gcc
    CXX=/usr/bin/aarch64-linux-gnu-g++
    " | tee "$(conan config home)/profiles/host"
    conan install .. --profile host --build missing
    source $INPUT_BUILD_TYPE/generators/conanbuild.sh
    PKG_CONFIG_PATH=/local/lib/pkgconfig cmake .. -DCMAKE_BUILD_TYPE=$INPUT_BUILD_TYPE \
     -DCMAKE_PROJECT_TOP_LEVEL_INCLUDES=./cmake/conan_provider.cmake -DASAN=$INPUT_ASAN \
     -DCONAN_HOST_PROFILE="host" -DCORRADE_RC_PROGRAM=$(command -v corrade-rc) \
     -DCONAN_INSTALL_ARGS=--build=never
  fi
  cmake --build . --config $INPUT_BUILD_TYPE -- -j 4
}

function move() {
  echo "========================= Compacting binary and copying ========================="
  cd /pktvisor-src/build/
  cp -rf /pktvisor-src/build/bin/pktvisord /github/workspace/
  strip -s /pktvisor-src/build/bin/crashpad_handler
  cp -rf /pktvisor-src/build/bin/crashpad_handler /github/workspace/
  cp -rf /pktvisor-src/build/bin/pktvisor-reader /github/workspace/
  cp -rf /pktvisor-src/build/VERSION /github/workspace/
  cp -rf /pktvisor-src/build/p/ /github/workspace/build/
  cp -rf /pktvisor-src/golang/pkg/client/version.go /github/workspace/version.go
  cp -rf /pktvisor-src/src/tests/fixtures/pktvisor-port-service-names.csv /github/workspace/custom-iana.csv
}

function publishToBugsplat() {
  echo "========================= Publishing symbol to bugsplat ========================="
  cd /pktvisor-src/build/
  if [ "$INPUT_BUGSPLAT" == "true" ]; then
  wget https://github.com/orb-community/CrashpadTools/raw/main/linux/dump_syms
  chmod a+x ./dump_syms
  wget https://github.com/orb-community/CrashpadTools/raw/main/linux/symupload
  chmod a+x ./symupload
  ./dump_syms /github/workspace/pktvisord > pktvisor.sym
  PKTVISOR_VERSION=$(cat VERSION)
  ls -lha
  ./symupload -k $INPUT_BUGSPLAT_KEY pktvisor.sym $INPUT_BUGSPLAT_SYMBOL_URL$INPUT_ARCH$PKTVISOR_VERSION 2>/dev/null
  fi
}

validateParams
build
move
publishToBugsplat
