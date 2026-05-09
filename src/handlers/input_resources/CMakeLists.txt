message(STATUS "Handler Module: Input Resources")

add_library(VisorHandlerInputResources STATIC
        InputResourcesHandlerModulePlugin.cpp
        InputResourcesStreamHandler.cpp
        )
add_library(Visor::Handler::InputResources ALIAS VisorHandlerInputResources)

target_include_directories(VisorHandlerInputResources
        INTERFACE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
        )

target_link_libraries(VisorHandlerInputResources
        PUBLIC
        Visor::Input::Pcap
        Visor::Input::Dnstap
        Visor::Input::Mock
        Visor::Input::Flow
        Visor::Input::NetProbe
        )

set(VISOR_STATIC_PLUGINS ${VISOR_STATIC_PLUGINS} Visor::Handler::InputResources PARENT_SCOPE)

## TEST SUITE
add_executable(unit-tests-handler-input-resources test_resources_layer.cpp)

target_link_libraries(unit-tests-handler-input-resources
        PRIVATE
        Visor::Handler::InputResources
        Visor::Lib::Test)

add_test(NAME unit-tests-handler-input-resources
        WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}/src
        COMMAND unit-tests-handler-input-resources)