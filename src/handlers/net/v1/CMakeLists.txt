message(STATUS "Handler Module: Net")

set_directory_properties(PROPERTIES CORRADE_USE_PEDANTIC_FLAGS ON)

corrade_add_static_plugin(VisorHandlerNet
        ${CMAKE_CURRENT_BINARY_DIR}
        NetHandler.conf
        NetHandlerModulePlugin.cpp
        NetStreamHandler.cpp)
add_library(Visor::Handler::Net ALIAS VisorHandlerNet)

target_include_directories(VisorHandlerNet
        INTERFACE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
        )

target_link_libraries(VisorHandlerNet
        PUBLIC
        Visor::Lib::Tcp
        Visor::Input::Pcap
        Visor::Input::Dnstap
        Visor::Input::Mock
        )

set(VISOR_STATIC_PLUGINS ${VISOR_STATIC_PLUGINS} Visor::Handler::Net PARENT_SCOPE)


## TEST SUITE
if(WIN32)
    #dnstap not supported
    add_executable(unit-tests-handler-net tests/test_json_schema.cpp)
else()
    add_executable(unit-tests-handler-net
            tests/test_net_layer.cpp
            tests/test_json_schema.cpp)
endif()

find_package(nlohmann_json_schema_validator REQUIRED)

target_link_libraries(unit-tests-handler-net
        PRIVATE
        nlohmann_json_schema_validator
        Visor::Handler::Net
        Visor::Handler::Dns
        Visor::Lib::Test)

add_test(NAME unit-tests-handler-net
        WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}/src
        COMMAND unit-tests-handler-net)
