message(STATUS "Visor Lib DNS Helper")

find_package(PcapPlusPlus REQUIRED)
find_package(Catch2 REQUIRED)
find_package(fmt REQUIRED)

add_library(VisorLibDns
        dns.cpp
        DnsLayer.cpp
        DnsResource.cpp
        DnsResourceData.cpp
        )
add_library(Visor::Lib::Dns ALIAS VisorLibDns)

target_include_directories(VisorLibDns
        PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
        )

target_link_libraries(VisorLibDns
        PUBLIC
        Visor::Lib::Tcp
        PcapPlusPlus::PcapPlusPlus
        fmt::fmt
        )

## TEST SUITE
add_executable(unit-tests-visor-dns
        tests/test_dns.cpp
        tests/benchmark_dns.cpp)

target_link_libraries(unit-tests-visor-dns
        PRIVATE
        Visor::Lib::Dns
        Catch2::Catch2WithMain)

add_test(NAME unit-tests-visor-dns
        WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}/libs/visor_dns
        COMMAND unit-tests-visor-dns)