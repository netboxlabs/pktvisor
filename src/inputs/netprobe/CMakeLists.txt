message(STATUS "Input Module: Net Probe")

add_library(VisorInputNetProbe STATIC
        NetProbeInputModulePlugin.cpp
        NetProbeInputStream.cpp
        DohProbe.cpp
        HttpProbe.cpp
        PingProbe.cpp
        TcpProbe.cpp
        )
add_library(Visor::Input::NetProbe ALIAS VisorInputNetProbe)

target_include_directories(VisorInputNetProbe
        INTERFACE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
        )

find_package(uvw REQUIRED)

target_link_libraries(VisorInputNetProbe
        PUBLIC
        Visor::Core
        Visor::Lib::Tcp
        Visor::Lib::Dns
        Visor::Lib::Http
        uvw::uvw
        )

set(VISOR_STATIC_PLUGINS ${VISOR_STATIC_PLUGINS} Visor::Input::NetProbe PARENT_SCOPE)

## TEST SUITE
add_executable(unit-tests-input-netprobe test_netprobe.cpp)

target_link_libraries(unit-tests-input-netprobe
        PRIVATE
        Visor::Handler::NetProbe
        Visor::Lib::Test
        httplib::httplib)

add_test(NAME unit-tests-input-netprobe
        WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}/src
        COMMAND unit-tests-input-netprobe)