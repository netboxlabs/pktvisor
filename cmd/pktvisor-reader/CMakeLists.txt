add_executable(pktvisor-reader main.cpp)

find_package(docopt REQUIRED)

target_link_libraries(pktvisor-reader
        PRIVATE
        docopt_s
        # See pktvisord/CMakeLists.txt for why --start-group / --end-group is needed.
        $<$<CXX_COMPILER_ID:GNU>:-Wl,--start-group>
        Visor::Core
        ${VISOR_STATIC_PLUGINS}
        $<$<CXX_COMPILER_ID:GNU>:-Wl,--end-group>
        )

set_target_properties(pktvisor-reader
        PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${PROJECT_BINARY_DIR}/bin"
        RUNTIME_OUTPUT_DIRECTORY_DEBUG "${PROJECT_BINARY_DIR}/bin"
        RUNTIME_OUTPUT_DIRECTORY_RELEASE "${PROJECT_BINARY_DIR}/bin"
        RUNTIME_OUTPUT_DIRECTORY_RELWITHDEBINFO "${PROJECT_BINARY_DIR}/bin"
        RUNTIME_OUTPUT_DIRECTORY_MINSIZEREL "${PROJECT_BINARY_DIR}/bin"
        )