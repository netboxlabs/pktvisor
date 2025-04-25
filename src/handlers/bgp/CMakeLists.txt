message(STATUS "Handler Module: BGP")

set_directory_properties(PROPERTIES CORRADE_USE_PEDANTIC_FLAGS ON)

corrade_add_static_plugin(VisorHandlerBgp
        ${CMAKE_CURRENT_BINARY_DIR}
        BgpHandler.conf
        BgpHandlerModulePlugin.cpp
        BgpStreamHandler.cpp)
add_library(Visor::Handler::Bgp ALIAS VisorHandlerBgp)

target_include_directories(VisorHandlerBgp
        INTERFACE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>)

target_link_libraries(VisorHandlerBgp
        PUBLIC
        Visor::Input::Pcap)

set(VISOR_STATIC_PLUGINS ${VISOR_STATIC_PLUGINS} Visor::Handler::Bgp PARENT_SCOPE)

## TEST SUITE
add_executable(unit-tests-handler-bgp
        tests/test_bgp_layer.cpp
        tests/test_json_schema.cpp)

find_package(nlohmann_json_schema_validator REQUIRED)

target_link_libraries(unit-tests-handler-bgp
        PRIVATE
        nlohmann_json_schema_validator
        Visor::Handler::Bgp
        Visor::Lib::Test)

add_test(NAME unit-tests-handler-bgp
        WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}/src
        COMMAND unit-tests-handler-bgp)