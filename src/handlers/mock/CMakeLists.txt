message(STATUS "Handler Module: Mock")

add_library(VisorHandlerMock STATIC
        MockHandlerModulePlugin.cpp
        MockStreamHandler.cpp)
add_library(Visor::Handler::Mock ALIAS VisorHandlerMock)

target_include_directories(VisorHandlerMock
        INTERFACE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
        )

target_link_libraries(VisorHandlerMock
        PUBLIC
        Visor::Input::Mock
        )

set(VISOR_STATIC_PLUGINS ${VISOR_STATIC_PLUGINS} Visor::Handler::Mock PARENT_SCOPE)
