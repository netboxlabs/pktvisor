# Design: Replace Conan `corrade/2020.06` with Local Recipe at Git Commit `22e7ffc6`

**Date:** 2026-03-27
**Status:** Approved

---

## Problem

pktvisor's build depends on `corrade/2020.06` from Conan Center Index (CCI). This version is from June 2020 and fails to compile with GCC 11/12 and Clang 14+ due to known upstream issues (#136, #164). No newer Corrade version exists in CCI (only `2020.06` and `2019.10` are published; the `2025.0a` release is ~81% complete upstream but not yet tagged).

## Goal

Fix the build on modern compilers with zero C++ source changes and zero CMakeLists.txt changes, while keeping Conan as the sole dependency manager.

## Solution: A1 — Local Conan Recipe at Specific Git Commit

Store a minimal Conan recipe inside the pktvisor repo that builds Corrade from a known-good commit on the `master` branch (`22e7ffc6fcdeaa0df96e0d8b3d482ad6abe7dc36`). This commit contains all GCC 11/12/13 and Clang 14/15/16 fixes that were merged after the 2020.06 release but never formally tagged.

### Why this commit?

Commit `22e7ffc6` on the Corrade `master` branch post-dates the fixes for:
- **Issue #136**: `constexpr` lambda failure with GCC 11/12 and Clang 11–14
- **Issue #164**: `strerror_r` type mismatch on Clang 14 / FreeBSD

No patches are needed — the fixes are baked into the source at this commit.

### Future migration path

When Corrade `2025.0a` is tagged and appears in Conan Center:
1. Delete `recipes/corrade/`
2. Bump the version string in `conanfile.py` from `cci.20250327` to `2025.0a`
3. Remove the `conan create` bootstrap step from CI

---

## Repository Changes

### New directory structure

```
recipes/corrade/
├── all/
│   ├── conanfile.py                    # Adapted from CCI (patches removed)
│   ├── conandata.yml                   # Points to commit tarball
│   └── cmake/
│       └── conan-corrade-vars.cmake    # Copied verbatim from CCI
└── config.yml                          # Declares version cci.20250327
```

### `recipes/corrade/config.yml`

```yaml
versions:
  "cci.20250327":
    folder: all
```

### `recipes/corrade/all/conandata.yml`

```yaml
sources:
  "cci.20250327":
    url: "https://github.com/mosra/corrade/archive/22e7ffc6fcdeaa0df96e0d8b3d482ad6abe7dc36.tar.gz"
    sha256: "<computed during implementation with `sha256sum` or `conan download`>"
```

The SHA256 must be computed during implementation by downloading the tarball once:
```bash
curl -L https://github.com/mosra/corrade/archive/22e7ffc6fcdeaa0df96e0d8b3d482ad6abe7dc36.tar.gz | sha256sum
```

### `recipes/corrade/all/conanfile.py`

Based verbatim on the CCI recipe with two modifications:
1. Remove `export_conandata_patches` from `export_sources()`
2. Remove `apply_conandata_patches` from `build()`

All other recipe logic (options, CMake variables, `package_info()` components, `UseCorrade.cmake` installation) remains identical to the CCI recipe.

### `recipes/corrade/all/cmake/conan-corrade-vars.cmake`

Copied verbatim from CCI. This file reads `configure.h` to extract Corrade feature flags and sets up the `Corrade::rc` imported executable target.

---

## Main `conanfile.py` changes (pktvisor root)

```python
# requirements():
# Before: self.requires("corrade/2020.06")
self.requires("corrade/cci.20250327")

# build_requirements():
# Before: self.tool_requires("corrade/2020.06")
self.tool_requires("corrade/cci.20250327")
```

---

## Build Workflow

A one-time bootstrap step must run before `conan install` in any clean environment:

```bash
conan create recipes/corrade/all --version cci.20250327 --build=missing
```

After this, the normal build is unchanged:

```bash
conan install . --build=missing -s build_type=Release
cmake -B build -DCMAKE_TOOLCHAIN_FILE=build/Release/generators/conan_toolchain.cmake
cmake --build build
```

The bootstrapped package is cached in `~/.conan2/` and does not need to be re-created on subsequent builds unless the cache is cleared.

### CI changes

Add one line before the existing `conan install` step in all CI pipeline definitions:

```yaml
# Before conan install:
- run: conan create recipes/corrade/all --version cci.20250327 --build=missing
```

### Local developer setup

Add the bootstrap command to the project's developer setup documentation (README or CONTRIBUTING).

---

## What Does NOT Change

| Artifact | Change |
|---|---|
| All `.cpp` / `.h` files | None |
| All `CMakeLists.txt` files | None |
| All plugin `.conf` files | None |
| `find_package(Corrade REQUIRED)` in root CMakeLists.txt | None |
| All `corrade_add_static_plugin()` calls | None |
| All `CORRADE_PLUGIN_REGISTER` macros | None |
| All other Conan dependencies | None |

---

## Risk Assessment

| Risk | Likelihood | Mitigation |
|---|---|---|
| `conan-corrade-vars.cmake` cmake helper incompatible with master source | Low | The file reads from `configure.h` which exists on master; same logic applies |
| GitHub commit tarball URL changes | Very low | GitHub commit-based archives are permanent |
| Master-branch Corrade API incompatible with pktvisor source | Very low | API is backward-compatible; master only adds fixes and new features |
| Cross-compilation (`tool_requires`) needs separate create step | Medium | The CCI recipe handles this via `cross_building()` check; same logic preserved |

---

## Files Touched

1. `conanfile.py` — 2 line changes (version bump in `requires` and `tool_requires`)
2. `recipes/corrade/config.yml` — new file
3. `recipes/corrade/all/conandata.yml` — new file
4. `recipes/corrade/all/conanfile.py` — new file (adapted from CCI)
5. `recipes/corrade/all/cmake/conan-corrade-vars.cmake` — new file (verbatim from CCI)
6. CI pipeline file(s) — add `conan create` bootstrap step
