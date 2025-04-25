message(STATUS "Visor Lib Test Helper")

find_package(spdlog REQUIRED)
find_package(Catch2 REQUIRED)

add_library(VisorLibTest INTERFACE)
add_library(Visor::Lib::Test ALIAS VisorLibTest)

target_include_directories(VisorLibTest
    INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>)

target_link_libraries(VisorLibTest
    INTERFACE
    spdlog::spdlog
    Catch2::Catch2WithMain)

target_compile_features(VisorLibTest INTERFACE cxx_std_17)

target_sources(VisorLibTest INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/catch2/catch_test_visor.hpp)