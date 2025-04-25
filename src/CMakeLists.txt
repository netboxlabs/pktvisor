
message(STATUS "visor-core")

set_directory_properties(PROPERTIES CORRADE_USE_PEDANTIC_FLAGS ON)

find_package(Protobuf REQUIRED)
find_package(fmt REQUIRED)
find_package(httplib REQUIRED)
find_package(maxminddb REQUIRED)
find_package(nlohmann_json REQUIRED)
find_package(fast-cpp-csv-parser REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(PalSigslot REQUIRED)
find_package(robin_hood REQUIRED)
find_package(spdlog REQUIRED)
find_package(yaml-cpp REQUIRED)
find_package(Catch2 REQUIRED)
find_package(opentelemetry-cpp REQUIRED)

add_library(visor-core
        AbstractModule.cpp
        AbstractPlugin.cpp
        InputModulePlugin.cpp
        HandlerModulePlugin.cpp
        GeoDB.cpp
        CoreServer.cpp
        CoreRegistry.cpp
        Metrics.cpp
        Policies.cpp
        ThreadName.cpp
        IpPort.cpp
        Taps.cpp)
add_library(Visor::Core ALIAS visor-core)

target_include_directories(visor-core
        PUBLIC
        ${CMAKE_CURRENT_BINARY_DIR} # Visor::Core config.h
        INTERFACE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
        $<BUILD_INTERFACE:${GENERATED_PROTOBUF_PATH}> # for generated otel proto headers
        )

target_link_libraries(visor-core
        PUBLIC
        datasketches
        rng
        timer
        opentelemetry-cpp::opentelemetry_proto
        protobuf::libprotobuf
        maxminddb::maxminddb
        Corrade::Corrade
        spdlog::spdlog
        fmt::fmt
        httplib::httplib
        nlohmann_json::nlohmann_json
        fast-cpp-csv-parser::fast-cpp-csv-parser
        Pal::Sigslot
        robin_hood::robin_hood
        yaml-cpp::yaml-cpp
        OpenSSL::SSL
        ${VISOR_STATIC_PLUGINS}
        )

configure_file(visor_config.h.in visor_config.h @ONLY)

add_subdirectory(inputs)
add_subdirectory(handlers)

set(VISOR_STATIC_PLUGINS ${VISOR_STATIC_PLUGINS} PARENT_SCOPE)

## TEST SUITE
add_executable(unit-tests-visor-core
        tests/test_sketches.cpp
        tests/test_metrics.cpp
        tests/test_geoip.cpp
        tests/test_ipport.cpp
        tests/test_taps.cpp
        tests/test_policies.cpp
        tests/test_handlers.cpp
        )

target_include_directories(unit-tests-visor-core PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

target_link_libraries(unit-tests-visor-core 
        PRIVATE
        Visor::Core
        ${VISOR_STATIC_PLUGINS}
        Catch2::Catch2WithMain)

add_test(NAME unit-tests-visor-core
        WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}/src
        COMMAND unit-tests-visor-core)