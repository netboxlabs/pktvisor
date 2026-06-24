
add_library(timer INTERFACE)

target_include_directories(timer
        INTERFACE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
        )

target_compile_features(timer INTERFACE cxx_std_17)

target_sources(timer
        INTERFACE
        ${CMAKE_CURRENT_SOURCE_DIR}/timer.hpp
        ${CMAKE_CURRENT_SOURCE_DIR}/event.hpp
        )