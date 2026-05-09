message(STATUS "Input Module: Flow")

add_library(VisorInputFlow STATIC
        FlowInputModulePlugin.cpp
        FlowInputStream.cpp
        )
add_library(Visor::Input::Flow ALIAS VisorInputFlow)

target_include_directories(VisorInputFlow
        INTERFACE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
        )

find_package(PcapPlusPlus REQUIRED)
find_package(uvw REQUIRED)

target_link_libraries(VisorInputFlow
        PUBLIC
        netflow
        sflow
        Visor::Core
        PcapPlusPlus::PcapPlusPlus
        uvw::uvw
        )

set(VISOR_STATIC_PLUGINS ${VISOR_STATIC_PLUGINS} Visor::Input::Flow PARENT_SCOPE)

## TEST SUITE
add_executable(unit-tests-input-flow test_flow.cpp)

target_link_libraries(unit-tests-input-flow
        PRIVATE 
        Visor::Input::Flow
        Visor::Lib::Test)

add_test(NAME unit-tests-input-flow
        WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}/src
        COMMAND unit-tests-input-flow)