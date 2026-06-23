
message(STATUS "3rd party libraries")

add_subdirectory(datasketches)
add_subdirectory(netflow)
add_subdirectory(sflow)
add_subdirectory(timer)
if(NOT WIN32)
    add_subdirectory(fstrm)
endif()
