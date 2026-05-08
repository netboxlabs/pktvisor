
set(FIXTURE_DIR ${PROJECT_SOURCE_DIR}/src/tests/fixtures)
set(HOST_VAR "-H 127.0.0.1/32")
set(PCAP_BINARY ${CMAKE_BINARY_DIR}/bin/pktvisor-reader)
set(PKTD_BINARY ${CMAKE_BINARY_DIR}/bin/pktvisord)
set(VISOR_DYNMODULE_DIR ${CMAKE_BINARY_DIR}/lib/)
set(INT_SH ${PROJECT_SOURCE_DIR}/integration_tests/integration.sh)
set(WORKING_DIR ${PROJECT_SOURCE_DIR}/integration_tests)

macro(visor_pcap_int_test name)
    add_test(NAME ${name}
            WORKING_DIRECTORY ${WORKING_DIR}
            COMMAND ${INT_SH} ${PCAP_BINARY} -- ${HOST_VAR} --geo-city ${FIXTURE_DIR}/GeoIP2-City-Test.mmdb --geo-asn ${FIXTURE_DIR}/GeoIP2-ISP-Test.mmdb ${FIXTURE_DIR}/${name}.pcap)
endmacro()

visor_pcap_int_test(dns_ipv4_udp)
visor_pcap_int_test(dns_ipv4_tcp)
visor_pcap_int_test(dns_ipv6_udp)
visor_pcap_int_test(dns_ipv6_tcp)
visor_pcap_int_test(dhcp-flow)

# this allows local, non-public integration tests (for example, on private pcap data)
#add_test(NAME external-tests
#        WORKING_DIRECTORY ${WORKING_DIR}
#        COMMAND ${PROJECT_SOURCE_DIR}/integration_tests/external.sh ${PCAP_BINARY}
#        )
