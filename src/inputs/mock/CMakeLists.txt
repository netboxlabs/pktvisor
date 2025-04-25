message(STATUS "Input Module: Mock")

set_directory_properties(PROPERTIES CORRADE_USE_PEDANTIC_FLAGS ON)

corrade_add_static_plugin(VisorInputMock ${CMAKE_CURRENT_BINARY_DIR}
        VisorInputMock.conf
        MockInputModulePlugin.cpp
        MockInputStream.cpp
        )
add_library(Visor::Input::Mock ALIAS VisorInputMock)

target_include_directories(VisorInputMock
        INTERFACE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
        )

target_link_libraries(VisorInputMock
        PUBLIC
        Visor::Core
        )

set(VISOR_STATIC_PLUGINS ${VISOR_STATIC_PLUGINS} Visor::Input::Mock PARENT_SCOPE)

## TEST SUITE
add_executable(unit-tests-input-mock test_mock.cpp)

find_package(Catch2 REQUIRED)

target_link_libraries(unit-tests-input-mock
        PRIVATE
        Visor::Input::Mock
        Catch2::Catch2WithMain)

add_test(NAME unit-tests-input-mock
        WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}/src
        COMMAND unit-tests-input-mock)
