message(STATUS "Handler Module: Net Probe")

add_library(VisorHandlerNetProbe STATIC
        NetProbeHandlerModulePlugin.cpp
        NetProbeStreamHandler.cpp
        )
add_library(Visor::Handler::NetProbe ALIAS VisorHandlerNetProbe)

target_include_directories(VisorHandlerNetProbe
        INTERFACE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
        )

target_link_libraries(VisorHandlerNetProbe
        PUBLIC
        Visor::Lib::Transaction
        Visor::Input::NetProbe
        Visor::Lib::Dns
        )

set(VISOR_STATIC_PLUGINS ${VISOR_STATIC_PLUGINS} Visor::Handler::NetProbe PARENT_SCOPE)


## TEST SUITE
add_executable(unit-tests-handler-netprobe test_net_probe.cpp)

target_link_libraries(unit-tests-handler-netprobe
        PRIVATE
        Visor::Handler::NetProbe
        Visor::Lib::Test)

add_test(NAME unit-tests-handler-netprobe
        WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}/src
        COMMAND unit-tests-handler-netprobe)
