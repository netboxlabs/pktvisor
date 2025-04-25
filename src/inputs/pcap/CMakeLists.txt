message(STATUS "Input Module: Pcap")

set_directory_properties(PROPERTIES CORRADE_USE_PEDANTIC_FLAGS ON)

corrade_add_static_plugin(VisorInputPcap ${CMAKE_CURRENT_BINARY_DIR}
        PcapInput.conf
        PcapInputModulePlugin.cpp
        PcapInputStream.cpp
        afpacket.cpp
        )
add_library(Visor::Input::Pcap ALIAS VisorInputPcap)

target_include_directories(VisorInputPcap
        INTERFACE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
        )

target_link_libraries(VisorInputPcap
        PUBLIC
        Visor::Core
        Visor::Lib::Utils
        )

set(VISOR_STATIC_PLUGINS ${VISOR_STATIC_PLUGINS} Visor::Input::Pcap PARENT_SCOPE)

## TEST SUITE
add_executable(unit-tests-input-pcap
        tests/test_mock_traffic.cpp
        tests/test_parse_pcap.cpp)

find_package(Catch2 REQUIRED)

target_link_libraries(unit-tests-input-pcap
        PRIVATE Visor::Input::Pcap
        Catch2::Catch2WithMain)

add_test(NAME unit-tests-input-pcap
        WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}/src
        COMMAND unit-tests-input-pcap)