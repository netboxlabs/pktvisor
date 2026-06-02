#!/bin/sh
#
build() {
  echo "========================= Building pktvisor-cli ========================="
  cp -rf golang/ /src/
  # Copying this from previous build (cpp)
  cp -rf ./version.go /src/pkg/client/version.go
  cd /src
  # CGO_ENABLED=0 produces a portable static binary that runs on the glibc
  # runtime image, even though it is built on an Alpine/musl toolchain.
  CGO_ENABLED=0 GOOS=$INPUT_GOOS GOARCH=$INPUT_GOARCH go build -o pktvisor-cli cmd/pktvisor-cli/main.go
}

copy() {
  echo "========================= Copying binary ========================="
  cp -rf /src/pktvisor-cli /github/workspace/
}

build
copy
