add_executable(pktvisor-pcap main.cpp)

find_package(docopt REQUIRED)

target_link_libraries(pktvisor-pcap
        PRIVATE
        docopt::docopt
        ${VISOR_STATIC_PLUGINS}
        )
