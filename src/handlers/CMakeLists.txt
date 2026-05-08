
add_subdirectory(net)
add_subdirectory(dns)
add_subdirectory(bgp)
add_subdirectory(flow)
add_subdirectory(dhcp)
add_subdirectory(pcap)
add_subdirectory(netprobe)
add_subdirectory(input_resources)

set(VISOR_STATIC_PLUGINS ${VISOR_STATIC_PLUGINS} PARENT_SCOPE)
