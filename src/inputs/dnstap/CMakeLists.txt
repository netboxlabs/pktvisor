message(STATUS "Input Module: Dnstap")

set_directory_properties(PROPERTIES CORRADE_USE_PEDANTIC_FLAGS ON)

protobuf_generate_cpp(PROTO_SRCS PROTO_HDRS pb/dnstap.proto)

if(NOT WIN32)
    # Suppress the warning for the generated files
    set_source_files_properties(${PROTO_SRCS} ${PROTO_HDRS}
        PROPERTIES COMPILE_FLAGS "-Wno-missing-declarations -Wno-unused-parameter"
    )
endif()

corrade_add_static_plugin(VisorInputDnstap ${CMAKE_CURRENT_BINARY_DIR}
        Dnstap.conf
        DnstapInputModulePlugin.cpp
        DnstapInputStream.cpp
        ${PROTO_SRCS}
        )
add_library(Visor::Input::Dnstap ALIAS VisorInputDnstap)

target_include_directories(VisorInputDnstap
        PRIVATE
        ${CMAKE_CURRENT_BINARY_DIR}
        INTERFACE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}> # for generated dnstap.pb.h
        )

if(NOT WIN32)
    set(DNSTAP_ADDITIONAL_LIBS fstrm)
endif()

find_package(uvw REQUIRED)

target_link_libraries(VisorInputDnstap
        PUBLIC
        ${DNSTAP_ADDITIONAL_LIBS}
        Visor::Core
        Visor::Lib::Utils
        uvw::uvw
        )

set(VISOR_STATIC_PLUGINS ${VISOR_STATIC_PLUGINS} Visor::Input::Dnstap PARENT_SCOPE)

## TEST SUITE
add_executable(unit-tests-input-dnstap tests/test_dnstap.cpp)

target_link_libraries(unit-tests-input-dnstap
        PRIVATE 
        Visor::Input::Dnstap
        Visor::Lib::Test)

add_test(NAME unit-tests-input-dnstap
        WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}/src
        COMMAND unit-tests-input-dnstap)