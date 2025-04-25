message(STATUS "Handler Module: DNS v2")

set_directory_properties(PROPERTIES CORRADE_USE_PEDANTIC_FLAGS ON)

corrade_add_static_plugin(VisorHandlerDnsV2
        ${CMAKE_CURRENT_BINARY_DIR}
        DnsHandler.conf
        DnsHandlerModulePlugin.cpp
        DnsStreamHandler.cpp
        )
add_library(Visor::Handler::Dns::V2 ALIAS VisorHandlerDnsV2)

target_include_directories(VisorHandlerDnsV2
        INTERFACE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
        )

target_link_libraries(VisorHandlerDnsV2
        PUBLIC
        Visor::Lib::Dns
        Visor::Lib::Transaction
        Visor::Input::Pcap
        Visor::Input::Dnstap
        Visor::Input::Mock
        )

set(VISOR_STATIC_PLUGINS ${VISOR_STATIC_PLUGINS} Visor::Handler::Dns::V2 PARENT_SCOPE)

## TEST SUITE
add_executable(unit-tests-handler-dns-v2
        tests/test_dns_layer.cpp
        tests/test_dnstap.cpp)

find_package(nlohmann_json_schema_validator REQUIRED)

target_link_libraries(unit-tests-handler-dns-v2
        PRIVATE
        nlohmann_json_schema_validator
        Visor::Handler::Dns::V2
        Visor::Lib::Test)

add_test(NAME unit-tests-handler-dns-v2
        WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}/src
        COMMAND unit-tests-handler-dns-v2)