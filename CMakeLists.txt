cmake_minimum_required(VERSION 3.24)

#######################################################
# VERSION
#######################################################

# this is the source of truth for semver version
project(visor VERSION 4.5.0)

# for main line release, this is empty
# for development release, this is "-develop"
# for release candidate, this is "-rc"
set(VISOR_PRERELEASE "-develop")

#######################################################

# if develop or rc build, add git hash
# note this only updates on cmake reconfigure, not every git commit
# so it's mainly useful for GitHub CI, not developers
if(VISOR_PRERELEASE STREQUAL "-develop" OR VISOR_PRERELEASE STREQUAL "-rc")
    execute_process(
            COMMAND
            git rev-parse --short HEAD
            WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
            RESULT_VARIABLE
            SHORT_HASH_RESULT
            OUTPUT_VARIABLE
            SHORT_HASH
            OUTPUT_STRIP_TRAILING_WHITESPACE
    )
    if ("${SHORT_HASH}" STREQUAL "")
        message(FATAL "Unable to get current git hash for develop/rc version")
    endif ()
    string(APPEND VISOR_PRERELEASE "-${SHORT_HASH}")
endif()

# these are computed
set(VISOR_VERSION_NUM "${PROJECT_VERSION}${VISOR_PRERELEASE}")
set(VISOR_VERSION "pktvisor ${PROJECT_VERSION}${VISOR_PRERELEASE}")

# used in CI
file(WRITE ${CMAKE_BINARY_DIR}/VERSION ${VISOR_VERSION_NUM})
# golang version
configure_file(golang/pkg/client/version.go.in ${PROJECT_SOURCE_DIR}/golang/pkg/client/version.go)

####### end version code #######

if(NOT DEFINED ENV{VERSION_ONLY})

list(APPEND CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake" ${CMAKE_BINARY_DIR})
list(APPEND CMAKE_PREFIX_PATH ${CMAKE_BINARY_DIR})

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
if(NOT MSVC)
    add_compile_options(-Wall -pedantic -W -Wextra -Wno-unknown-pragmas)
endif()

if(WIN32)
    set(CUSTOM_CMAKE_OPTIONS docopt.cpp:boost_regex=True)
endif()

find_package(Corrade REQUIRED)
include(sanitizer)
if(CODE_COVERAGE)
    include(CodeCoverage)
    append_coverage_compiler_flags()
    setup_target_for_coverage_lcov(
            NAME coverage
            EXECUTABLE ctest
            EXCLUDE "3rd/*" "cmd/*" "libs/*" "${PROJECT_BINARY_DIR}/*")
endif()

set(VISOR_STATIC_PLUGINS)

enable_testing()

message(STATUS "Building pktvisor version ${CMAKE_PROJECT_VERSION_MAJOR}.${CMAKE_PROJECT_VERSION_MINOR}.${CMAKE_PROJECT_VERSION_PATCH}${VISOR_PRERELEASE}")
add_subdirectory(3rd)
add_subdirectory(libs)
add_subdirectory(src)
add_subdirectory(cmd)
if(NOT WIN32)
add_subdirectory(integration_tests)
endif()

endif()
