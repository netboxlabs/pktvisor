message(STATUS "Handler Module: DNS")

set_directory_properties(PROPERTIES CORRADE_USE_PEDANTIC_FLAGS ON)

corrade_add_static_plugin(VisorHandlerDns
        ${CMAKE_CURRENT_BINARY_DIR}
        DnsHandler.conf
        DnsHandlerModulePlugin.cpp
        DnsStreamHandler.cpp
        )
add_library(Visor::Handler::Dns ALIAS VisorHandlerDns)

target_include_directories(VisorHandlerDns
        INTERFACE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
        )

target_link_libraries(VisorHandlerDns
        PUBLIC
        Visor::Lib::Dns
        Visor::Lib::Transaction
        Visor::Input::Pcap
        Visor::Input::Dnstap
        Visor::Input::Mock
        )

set(VISOR_STATIC_PLUGINS ${VISOR_STATIC_PLUGINS} Visor::Handler::Dns PARENT_SCOPE)

## TEST SUITE
add_executable(unit-tests-handler-dns
        tests/test_dns_layer.cpp
        tests/test_dnstap.cpp
        tests/test_json_schema.cpp)

find_package(nlohmann_json_schema_validator REQUIRED)

target_link_libraries(unit-tests-handler-dns
        PRIVATE
        nlohmann_json_schema_validator
        Visor::Handler::Dns
        Visor::Lib::Test)

add_test(NAME unit-tests-handler-dns
        WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}/src
        COMMAND unit-tests-handler-dns)