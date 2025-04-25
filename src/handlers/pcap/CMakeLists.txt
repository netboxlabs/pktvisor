message(STATUS "Handler Module: Pcap")

set_directory_properties(PROPERTIES CORRADE_USE_PEDANTIC_FLAGS ON)

corrade_add_static_plugin(VisorHandlerPcap
        ${CMAKE_CURRENT_BINARY_DIR}
        PcapHandler.conf
        PcapHandlerModulePlugin.cpp
        PcapStreamHandler.cpp)
add_library(Visor::Handler::Pcap ALIAS VisorHandlerPcap)

target_include_directories(VisorHandlerPcap
        INTERFACE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
        )

target_link_libraries(VisorHandlerPcap
        PUBLIC
        Visor::Input::Pcap
        )

set(VISOR_STATIC_PLUGINS ${VISOR_STATIC_PLUGINS} Visor::Handler::Pcap PARENT_SCOPE)


## TEST SUITE
add_executable(unit-tests-handler-pcap
        tests/test_pcap_layer.cpp
        tests/test_json_schema.cpp)

find_package(nlohmann_json_schema_validator REQUIRED)

target_link_libraries(unit-tests-handler-pcap
        PRIVATE
        nlohmann_json_schema_validator
        Visor::Handler::Pcap
        Visor::Lib::Test)

add_test(NAME unit-tests-handler-pcap
        WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}/src
        COMMAND unit-tests-handler-pcap)
