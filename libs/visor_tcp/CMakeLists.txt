message(STATUS "Visor Lib TCP Helper")

find_package(PcapPlusPlus REQUIRED)

add_library(VisorLibTcp VisorTcpLayer.cpp)

add_library(Visor::Lib::Tcp ALIAS VisorLibTcp)

target_include_directories(VisorLibTcp
        PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
        )

target_link_libraries(VisorLibTcp
        PUBLIC
        PcapPlusPlus::PcapPlusPlus
        )
