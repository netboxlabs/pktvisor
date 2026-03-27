# Corrade Local Conan Recipe Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the frozen `corrade/2020.06` Conan Center package with a local recipe that builds Corrade from commit `22e7ffc6fcdeaa0df96e0d8b3d482ad6abe7dc36`, fixing GCC 11+/Clang 14+ compilation failures.

**Architecture:** A `recipes/corrade/` directory is added to the repo containing a Conan recipe adapted from the official CCI recipe. The recipe fetches Corrade from a GitHub commit tarball instead of the `v2020.06` tag tarball. A `conan create` bootstrap step is added to all CI workflows before the cmake/conan-install phase.

**Tech Stack:** Conan 2.x, CMake 3.24+, C++17, GitHub Actions

**Working branch:** `chore/replace-corrade-conan-recipe`

---

## File Map

| Action | Path | Purpose |
|---|---|---|
| Create | `recipes/corrade/config.yml` | Declares version `cci.20250327` |
| Create | `recipes/corrade/all/conandata.yml` | Source URL + SHA256 for commit tarball |
| Create | `recipes/corrade/all/conanfile.py` | Conan recipe (adapted from CCI, patches removed) |
| Create | `recipes/corrade/all/cmake/conan-corrade-vars.cmake` | CMake helper (verbatim from CCI) |
| Modify | `conanfile.py` | Bump version `2020.06` → `cci.20250327` |
| Modify | `.github/workflows/build-develop.yml` | Add `conan create` before cmake (mac + linux jobs); remove mac workaround cxxflag |
| Modify | `.github/workflows/build-release.yml` | Add `conan create` before cmake |
| Modify | `.github/workflows/build_debug.yml` | Add `conan create` before cmake |
| Modify | `.github/workflows/build_cross.yml` | Add `conan create` before `conan install` |

---

## Task 1: Compute commit tarball SHA256

**Files:**
- Read: nothing (run command)

- [ ] **Step 1: Download the commit tarball and compute SHA256**

```bash
curl -sL https://github.com/mosra/corrade/archive/22e7ffc6fcdeaa0df96e0d8b3d482ad6abe7dc36.tar.gz | sha256sum
```

Expected output format: `<hash>  -`

- [ ] **Step 2: Record the hash**

Copy the 64-character hex hash. You will use it in Task 2, Step 2. Do not proceed until you have it.

---

## Task 2: Create the local Conan recipe files

**Files:**
- Create: `recipes/corrade/config.yml`
- Create: `recipes/corrade/all/conandata.yml`
- Create: `recipes/corrade/all/conanfile.py`
- Create: `recipes/corrade/all/cmake/conan-corrade-vars.cmake`

- [ ] **Step 1: Create `recipes/corrade/config.yml`**

```yaml
versions:
  "cci.20250327":
    folder: all
```

- [ ] **Step 2: Create `recipes/corrade/all/conandata.yml`**

Replace `<SHA256_FROM_TASK_1>` with the hash you computed in Task 1.

```yaml
sources:
  "cci.20250327":
    url: "https://github.com/mosra/corrade/archive/22e7ffc6fcdeaa0df96e0d8b3d482ad6abe7dc36.tar.gz"
    sha256: "<SHA256_FROM_TASK_1>"
```

- [ ] **Step 3: Create `recipes/corrade/all/conanfile.py`**

This is the CCI recipe with two lines removed: `export_conandata_patches` (from `export_sources`) and `apply_conandata_patches` (from `build`). No patches are needed for this master commit — the fixes are already in the source.

```python
import os

from conan import ConanFile
from conan.errors import ConanInvalidConfiguration
from conan.tools.build import cross_building
from conan.tools.cmake import CMake, CMakeDeps, CMakeToolchain, cmake_layout
from conan.tools.files import copy, get, rmdir
from conan.tools.microsoft import is_msvc, check_min_vs

required_conan_version = ">=1.52.0"


class CorradeConan(ConanFile):
    name = "corrade"
    description = "Corrade is a multiplatform utility library written in C++11/C++14."
    license = "MIT"
    url = "https://github.com/conan-io/conan-center-index"
    homepage = "https://magnum.graphics/corrade"
    topics = ("magnum", "filesystem", "console", "environment", "os")

    package_type = "library"
    settings = "os", "arch", "compiler", "build_type"
    options = {
        "shared": [True, False],
        "fPIC": [True, False],
        "build_deprecated": [True, False],
        "with_interconnect": [True, False],
        "with_main": [True, False],
        "with_pluginmanager": [True, False],
        "with_testsuite": [True, False],
        "with_utility": [True, False],
    }
    default_options = {
        "shared": False,
        "fPIC": True,
        "build_deprecated": True,
        "with_interconnect": True,
        "with_main": True,
        "with_pluginmanager": True,
        "with_testsuite": True,
        "with_utility": True,
    }

    def export_sources(self):
        copy(self, "cmake/*", src=self.recipe_folder, dst=self.export_sources_folder)

    def config_options(self):
        if self.settings.os == "Windows":
            del self.options.fPIC

    def configure(self):
        if self.options.shared:
            self.options.rm_safe("fPIC")

    def layout(self):
        cmake_layout(self, src_folder="src")

    def validate(self):
        check_min_vs(self, 190)
        if not self.options.with_utility and (
            self.options.with_testsuite or self.options.with_interconnect or self.options.with_pluginmanager
        ):
            raise ConanInvalidConfiguration(
                "Component 'utility' is required for 'test_suite', 'interconnect' and 'plugin_manager'"
            )

    def build_requirements(self):
        if hasattr(self, "settings_build") and cross_building(self, skip_x64_x86=True):
            self.tool_requires(f"corrade/{self.version}")

    def source(self):
        get(self, **self.conan_data["sources"][self.version], strip_root=True)

    def generate(self):
        tc = CMakeToolchain(self)
        tc.variables["BUILD_STATIC"] = not self.options.shared
        tc.variables["BUILD_STATIC_PIC"] = self.options.get_safe("fPIC", False)

        tc.variables["BUILD_DEPRECATED"] = self.options.build_deprecated
        tc.variables["WITH_INTERCONNECT"] = self.options.with_interconnect
        tc.variables["WITH_MAIN"] = self.options.with_main
        tc.variables["WITH_PLUGINMANAGER"] = self.options.with_pluginmanager
        tc.variables["WITH_TESTSUITE"] = self.options.with_testsuite
        tc.variables["WITH_UTILITY"] = self.options.with_utility
        tc.variables["WITH_RC"] = self.options.with_utility

        tc.variables["LIB_SUFFIX"] = ""

        if is_msvc(self):
            if check_min_vs(self, 193, raise_invalid=False):
                tc.variables["MSVC2019_COMPATIBILITY"] = True
            elif check_min_vs(self, 192, raise_invalid=False):
                tc.variables["MSVC2017_COMPATIBILITY"] = True
            elif check_min_vs(self, 191, raise_invalid=False):
                tc.variables["MSVC2015_COMPATIBILITY"] = True

        tc.generate()
        tc = CMakeDeps(self)
        tc.generate()

    def build(self):
        cmake = CMake(self)
        cmake.configure()
        cmake.build()

    def package(self):
        copy(self, "COPYING", dst=os.path.join(self.package_folder, "licenses"), src=self.source_folder)
        cmake = CMake(self)
        cmake.install()
        share_cmake = os.path.join(self.package_folder, "share", "cmake", "Corrade")
        copy(self, "UseCorrade.cmake",
             src=share_cmake,
             dst=os.path.join(self.package_folder, "lib", "cmake"))
        copy(self, "CorradeLibSuffix.cmake",
             src=share_cmake,
             dst=os.path.join(self.package_folder, "lib", "cmake"))
        copy(self, "*.cmake",
            src=os.path.join(self.export_sources_folder, "cmake"),
            dst=os.path.join(self.package_folder, "lib", "cmake"))
        rmdir(self, os.path.join(self.package_folder, "share"))

    def package_info(self):
        self.cpp_info.set_property("cmake_find_mode", "both")
        self.cpp_info.set_property("cmake_file_name", "Corrade")
        self.cpp_info.set_property("cmake_target_name", "Corrade::Corrade")

        suffix = "-d" if self.settings.build_type == "Debug" else ""

        cmake_modules = [
            os.path.join("lib", "cmake", "conan-corrade-vars.cmake"),
            os.path.join("lib", "cmake", "CorradeLibSuffix.cmake"),
            os.path.join("lib", "cmake", "UseCorrade.cmake"),
        ]
        self.cpp_info.set_property("cmake_build_modules", cmake_modules)
        self.cpp_info.components["_corrade"].build_modules["cmake_find_package"] = cmake_modules
        self.cpp_info.components["_corrade"].build_modules["cmake_find_package_multi"] = cmake_modules

        if self.options.with_main:
            self.cpp_info.components["main"].set_property("cmake_target_name", "Corrade::Main")
            self.cpp_info.components["main"].names["cmake_find_package"] = "Main"
            self.cpp_info.components["main"].names["cmake_find_package_multi"] = "Main"
            if self.settings.os == "Windows":
                self.cpp_info.components["main"].libs = ["CorradeMain" + suffix]
            self.cpp_info.components["main"].requires = ["_corrade"]

        if self.options.with_utility:
            self.cpp_info.components["utility"].set_property("cmake_target_name", "Corrade::Utility")
            self.cpp_info.components["utility"].names["cmake_find_package"] = "Utility"
            self.cpp_info.components["utility"].names["cmake_find_package_multi"] = "Utility"
            self.cpp_info.components["utility"].libs = ["CorradeUtility" + suffix]
            if self.settings.os in ["Linux", "FreeBSD"]:
                self.cpp_info.components["utility"].system_libs = ["m", "dl"]
            self.cpp_info.components["utility"].requires = ["_corrade"]

        if self.options.with_interconnect:
            self.cpp_info.components["interconnect"].set_property("cmake_target_name", "Corrade::Interconnect")
            self.cpp_info.components["interconnect"].names["cmake_find_package"] = "Interconnect"
            self.cpp_info.components["interconnect"].names["cmake_find_package_multi"] = "Interconnect"
            self.cpp_info.components["interconnect"].libs = ["CorradeInterconnect" + suffix]
            self.cpp_info.components["interconnect"].requires = ["utility"]

        if self.options.with_pluginmanager:
            self.cpp_info.components["plugin_manager"].set_property("cmake_target_name", "Corrade::PluginManager")
            self.cpp_info.components["plugin_manager"].names["cmake_find_package"] = "PluginManager"
            self.cpp_info.components["plugin_manager"].names["cmake_find_package_multi"] = "PluginManager"
            self.cpp_info.components["plugin_manager"].libs = ["CorradePluginManager" + suffix]
            self.cpp_info.components["plugin_manager"].requires = ["utility"]

        if self.options.with_testsuite:
            self.cpp_info.components["test_suite"].set_property("cmake_target_name", "Corrade::TestSuite")
            self.cpp_info.components["test_suite"].names["cmake_find_package"] = "TestSuite"
            self.cpp_info.components["test_suite"].names["cmake_find_package_multi"] = "TestSuite"
            self.cpp_info.components["test_suite"].libs = ["CorradeTestSuite" + suffix]
            self.cpp_info.components["test_suite"].requires = ["utility"]

        if self.options.with_utility:
            bindir = os.path.join(self.package_folder, "bin")
            self.output.info(f"Appending PATH environment variable: {bindir}")
            self.env_info.PATH.append(bindir)

        for key, component in self.cpp_info.components.items():
            component.set_property("pkg_config_name", f"{self.name}_{key}")

        self.cpp_info.names["cmake_find_package"] = "Corrade"
        self.cpp_info.names["cmake_find_package_multi"] = "Corrade"
```

- [ ] **Step 4: Create `recipes/corrade/all/cmake/conan-corrade-vars.cmake`**

Verbatim copy of the CCI helper file:

```cmake
# Here we are reproducing the variables and call performed by the FindCorrade.cmake provided by the library

# Read flags from configuration
file(READ "${CMAKE_CURRENT_LIST_DIR}/../../include/Corrade/configure.h" _corradeConfigure)
string(REGEX REPLACE ";" "\\\\;" _corradeConfigure "${_corradeConfigure}")
string(REGEX REPLACE "\n" ";" _corradeConfigure "${_corradeConfigure}")
set(_corradeFlags
    MSVC2015_COMPATIBILITY
    MSVC2017_COMPATIBILITY
    MSVC2019_COMPATIBILITY
    BUILD_DEPRECATED
    BUILD_STATIC
    BUILD_STATIC_UNIQUE_GLOBALS
    BUILD_MULTITHREADED
    TARGET_UNIX
    TARGET_APPLE
    TARGET_IOS
    TARGET_IOS_SIMULATOR
    TARGET_WINDOWS
    TARGET_WINDOWS_RT
    TARGET_EMSCRIPTEN
    TARGET_ANDROID
    # TARGET_X86 etc and TARGET_LIBCXX are not exposed to CMake as the meaning
    # is unclear on platforms with multi-arch binaries or when mixing different
    # STL implementations. TARGET_GCC etc are figured out via UseCorrade.cmake,
    # as the compiler can be different when compiling the lib & when using it.
    PLUGINMANAGER_NO_DYNAMIC_PLUGIN_SUPPORT
    TESTSUITE_TARGET_XCTEST
    UTILITY_USE_ANSI_COLORS)
foreach(_corradeFlag ${_corradeFlags})
    list(FIND _corradeConfigure "#define CORRADE_${_corradeFlag}" _corrade_${_corradeFlag})
    if(NOT _corrade_${_corradeFlag} EQUAL -1)
        set(CORRADE_${_corradeFlag} 1)
    endif()
endforeach()


# Corrade::rc, a target with just an executable
if(NOT TARGET Corrade::rc)
    if(CMAKE_CROSSCOMPILING)
        find_program(CORRADE_RC_PROGRAM
            NAMES corrade-rc
            PATHS ENV
            PATH NO_DEFAULT_PATH)
    else()
        find_program(CORRADE_RC_PROGRAM
            NAMES corrade-rc
            PATHS "${CMAKE_CURRENT_LIST_DIR}/../../bin/"
            NO_DEFAULT_PATH)
    endif()

    get_filename_component(CORRADE_RC_PROGRAM "${CORRADE_RC_PROGRAM}" ABSOLUTE)

    add_executable(Corrade::rc IMPORTED)
    set_property(TARGET Corrade::rc PROPERTY IMPORTED_LOCATION ${CORRADE_RC_PROGRAM})
endif()

# Include and declare other build modules
include("${CMAKE_CURRENT_LIST_DIR}/UseCorrade.cmake")
set(CORRADE_LIB_SUFFIX_MODULE "${CMAKE_CURRENT_LIST_DIR}/CorradeLibSuffix.cmake")
```

- [ ] **Step 5: Verify directory structure**

```bash
find recipes/corrade -type f | sort
```

Expected output:
```
recipes/corrade/all/cmake/conan-corrade-vars.cmake
recipes/corrade/all/conandata.yml
recipes/corrade/all/conanfile.py
recipes/corrade/config.yml
```

- [ ] **Step 6: Commit**

```bash
git add recipes/corrade/
git commit -m "chore: add local Corrade Conan recipe at commit 22e7ffc6

Builds Corrade from master commit 22e7ffc6 which contains GCC 11+
and Clang 14+ fixes not in the frozen corrade/2020.06 CCI package.

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>"
```

---

## Task 3: Verify recipe builds locally

**Files:**
- Read: `recipes/corrade/all/conanfile.py` (just created)

- [ ] **Step 1: Detect Conan profile (if not already done)**

```bash
conan profile detect -f
```

Expected: profile written to `~/.conan2/profiles/default` (or existing profile updated)

- [ ] **Step 2: Run `conan create` for the local recipe**

```bash
conan create recipes/corrade/all --version cci.20250327 --build=missing
```

Expected: output ends with something like:
```
corrade/cci.20250327: Package '...' created
```

If it fails with a SHA256 mismatch, the hash in `conandata.yml` is wrong — recompute it:
```bash
curl -sL https://github.com/mosra/corrade/archive/22e7ffc6fcdeaa0df96e0d8b3d482ad6abe7dc36.tar.gz | sha256sum
```
Then update `recipes/corrade/all/conandata.yml` with the correct value and retry.

- [ ] **Step 3: Confirm package is in local cache**

```bash
conan list "corrade/cci.20250327"
```

Expected output includes `corrade/cci.20250327`.

---

## Task 4: Update main conanfile.py

**Files:**
- Modify: `conanfile.py` (lines 11 and 40)

- [ ] **Step 1: Update `requirements()`**

In `conanfile.py`, change line 11:
```python
# Before
self.requires("corrade/2020.06")
# After
self.requires("corrade/cci.20250327")
```

- [ ] **Step 2: Update `build_requirements()`**

In `conanfile.py`, change line 40:
```python
# Before
self.tool_requires("corrade/2020.06")
# After
self.tool_requires("corrade/cci.20250327")
```

- [ ] **Step 3: Verify the full conanfile looks correct**

```bash
grep corrade conanfile.py
```

Expected output:
```
        self.requires("corrade/cci.20250327")
        self.tool_requires("corrade/cci.20250327")
```

No other lines should reference `corrade`.

- [ ] **Step 4: Verify local build resolves correctly**

From a clean build directory:
```bash
mkdir -p build_test && cd build_test
cmake .. -DCMAKE_BUILD_TYPE=Release -DCMAKE_PROJECT_TOP_LEVEL_INCLUDES=./cmake/conan_provider.cmake
```

Expected: cmake configure completes without Corrade-related errors. If Conan reports `corrade/cci.20250327 not found`, re-run Task 3.

- [ ] **Step 5: Commit**

```bash
git add conanfile.py
git commit -m "chore: bump Corrade to local recipe cci.20250327

Replaces the frozen corrade/2020.06 CCI package with a local recipe
that builds from master commit 22e7ffc6 to fix GCC 11+/Clang 14+ failures.

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>"
```

---

## Task 5: Update CI — build-develop.yml

**Files:**
- Modify: `.github/workflows/build-develop.yml`

There are **two jobs** in this file: `unit-tests-mac` (line 22) and `unit-tests-linux` (line 67). Both need a `conan create` step. The mac job also has a Corrade-specific cxxflag workaround (`-c=corrade/*:tools.build:cxxflags=['-include','vector']`) that should be removed since the root cause is fixed on master.

- [ ] **Step 1: Add `conan create` step to `unit-tests-mac` job**

After the `Detect Conan Profile` step (line ~50) and before the `Configure CMake` step (line ~52), insert:

```yaml
      - name: Bootstrap local Corrade recipe
        run: conan create ${{github.workspace}}/recipes/corrade/all --version cci.20250327 --build=missing
```

- [ ] **Step 2: Remove the mac-specific Corrade cxxflag workaround**

In the `Configure CMake` step of `unit-tests-mac`, the current run line is:
```yaml
        run: PKG_CONFIG_PATH=${{github.workspace}}/local/lib/pkgconfig cmake $GITHUB_WORKSPACE -DCMAKE_BUILD_TYPE=$BUILD_TYPE -DCMAKE_PROJECT_TOP_LEVEL_INCLUDES=./cmake/conan_provider.cmake -DCONAN_INSTALL_ARGS="--build=missing;-c=corrade/*:tools.build:cxxflags=['-include','vector']"
```

Change it to:
```yaml
        run: PKG_CONFIG_PATH=${{github.workspace}}/local/lib/pkgconfig cmake $GITHUB_WORKSPACE -DCMAKE_BUILD_TYPE=$BUILD_TYPE -DCMAKE_PROJECT_TOP_LEVEL_INCLUDES=./cmake/conan_provider.cmake -DCONAN_INSTALL_ARGS="--build=missing"
```

- [ ] **Step 3: Add `conan create` step to `unit-tests-linux` job**

After the `Detect Conan Profile` step (or after the `Setup Conan Cache` step if there's no profile detection step in this job) and before the `Configure CMake` step (line ~89), insert:

```yaml
      - name: Bootstrap local Corrade recipe
        run: conan create ${{github.workspace}}/recipes/corrade/all --version cci.20250327 --build=missing
```

- [ ] **Step 4: Commit**

```bash
git add .github/workflows/build-develop.yml
git commit -m "ci: add Corrade recipe bootstrap step to build-develop workflow

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>"
```

---

## Task 6: Update CI — build-release.yml

**Files:**
- Modify: `.github/workflows/build-release.yml`

- [ ] **Step 1: Add `conan create` step to `unit-tests` job**

After the `Setup Conan Cache` step (line ~38) and before the `Configure CMake` step (line ~42), insert:

```yaml
      - name: Bootstrap local Corrade recipe
        run: conan create ${{github.workspace}}/recipes/corrade/all --version cci.20250327 --build=missing
```

- [ ] **Step 2: Commit**

```bash
git add .github/workflows/build-release.yml
git commit -m "ci: add Corrade recipe bootstrap step to build-release workflow

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>"
```

---

## Task 7: Update CI — build_debug.yml

**Files:**
- Modify: `.github/workflows/build_debug.yml`

- [ ] **Step 1: Add `conan create` step to `code-coverage` job**

After the `Setup Conan Cache` step (line ~30) and before the `Configure CMake` step (line ~39), insert:

```yaml
      - name: Bootstrap local Corrade recipe
        run: conan create ${{github.workspace}}/recipes/corrade/all --version cci.20250327 --build=missing
```

- [ ] **Step 2: Commit**

```bash
git add .github/workflows/build_debug.yml
git commit -m "ci: add Corrade recipe bootstrap step to build_debug workflow

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>"
```

---

## Task 8: Update CI — build_cross.yml

**Files:**
- Modify: `.github/workflows/build_cross.yml`

The cross-compile workflow is different: `conan install` runs explicitly (line 128) before cmake. The `conan create` must run before that `conan install` step. The `conan create` here needs to use the default (build host) profile since the recipe will be consumed as a `tool_requires`.

- [ ] **Step 1: Add `conan create` step before `Install dependencies`**

After the `Setup Conan Cache` step (line ~118) and before the `Install dependencies` step (line ~125), insert:

```yaml
      - name: Bootstrap local Corrade recipe
        working-directory: ${{github.workspace}}/src
        run: conan create recipes/corrade/all --version cci.20250327 -pr:b=default --build=missing
```

Note: `-pr:b=default` is explicit here because the cross-compile context has both host and build profiles. The Corrade recipe will be used as `tool_requires` (build profile) so we create it with the build profile.

- [ ] **Step 2: Commit**

```bash
git add .github/workflows/build_cross.yml
git commit -m "ci: add Corrade recipe bootstrap step to build_cross workflow

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>"
```

---

## Task 9: Final verification

- [ ] **Step 1: Check all workflow files reference the bootstrap step**

```bash
grep -l "Bootstrap local Corrade" .github/workflows/*.yml
```

Expected output (4 files):
```
.github/workflows/build-develop.yml
.github/workflows/build-release.yml
.github/workflows/build_debug.yml
.github/workflows/build_cross.yml
```

- [ ] **Step 2: Confirm no remaining references to `corrade/2020.06`**

```bash
grep -r "corrade/2020.06" .
```

Expected: no output.

- [ ] **Step 3: Confirm local build passes tests (optional but recommended)**

```bash
mkdir -p build_verify && cd build_verify
cmake .. -DCMAKE_BUILD_TYPE=Release -DCMAKE_PROJECT_TOP_LEVEL_INCLUDES=./cmake/conan_provider.cmake
cmake --build . -- -j4
ctest --output-on-failure
```

Expected: all tests pass.

- [ ] **Step 4: Final commit (if Step 3 required any fixes)**

Only needed if Step 3 revealed issues that required fixes.

```bash
git add -A
git commit -m "chore: fix post-verification issues with Corrade recipe

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>"
```

---

## Notes for Future Maintainers

**When Corrade `2025.0a` lands in Conan Center:**
1. Delete `recipes/corrade/`
2. In `conanfile.py`: change `cci.20250327` → `2025.0a` in both `requires` and `build_requirements`
3. In all 4 CI workflow files: remove the `Bootstrap local Corrade recipe` step
4. Commit and PR

**If the commit `22e7ffc6` needs to be updated to a newer master commit:**
1. Compute new SHA256: `curl -sL https://github.com/mosra/corrade/archive/<new-commit>.tar.gz | sha256sum`
2. Update `recipes/corrade/all/conandata.yml`: change both the URL commit hash and the sha256
3. Update the version name in `config.yml`, `conandata.yml`, `conanfile.py` (root), and all 4 CI workflow files
4. Re-run `conan create recipes/corrade/all --version <new-version> --build=missing` locally to verify
