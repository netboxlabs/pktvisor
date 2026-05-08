add_executable(pktvisord main.cpp)

find_package(docopt REQUIRED)

if(NOT WIN32)
    set(ADDITIONAL_LIBS resolv)
endif()

if(NOT CRASHPAD_NOT_SUPPORTED)
    find_package(crashpad REQUIRED CONFIG)
    set(ADDITIONAL_LIBS ${ADDITIONAL_LIBS} crashpad::handler)
endif()

target_link_libraries(pktvisord
        PRIVATE
        timer
        ${ADDITIONAL_LIBS}
        docopt_s
        # CoreRegistry references plugin factory symbols and plugins link back
        # to Visor::Core — a real cycle. GNU ld is single-pass so it needs
        # --start-group / --end-group around the cyclic archives. ld64 (macOS)
        # and MSVC's link.exe handle this natively and don't accept the flag.
        $<$<CXX_COMPILER_ID:GNU>:-Wl,--start-group>
        Visor::Core
        ${VISOR_STATIC_PLUGINS}
        $<$<CXX_COMPILER_ID:GNU>:-Wl,--end-group>
        )

set_target_properties(pktvisord
        PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${PROJECT_BINARY_DIR}/bin"
        RUNTIME_OUTPUT_DIRECTORY_DEBUG "${PROJECT_BINARY_DIR}/bin"
        RUNTIME_OUTPUT_DIRECTORY_RELEASE "${PROJECT_BINARY_DIR}/bin"
        RUNTIME_OUTPUT_DIRECTORY_RELWITHDEBINFO "${PROJECT_BINARY_DIR}/bin"
        RUNTIME_OUTPUT_DIRECTORY_MINSIZEREL "${PROJECT_BINARY_DIR}/bin"
        )

#copy conan crashpad built binary to binaries folder
if(NOT CRASHPAD_NOT_SUPPORTED)
   list(GET crashpad_INCLUDE_DIR 0 first_path)
    set(CONAN_BIN_DIRS_SENTRY-CRASHPAD ${first_path}/../bin)
    if(WIN32)
        configure_file("${CONAN_BIN_DIRS_SENTRY-CRASHPAD}/crashpad_handler.exe" "${PROJECT_BINARY_DIR}/bin/crashpad_handler.exe" COPYONLY)
    else()
        configure_file("${CONAN_BIN_DIRS_SENTRY-CRASHPAD}/crashpad_handler" "${PROJECT_BINARY_DIR}/bin/crashpad_handler" COPYONLY)
    endif()
endif()