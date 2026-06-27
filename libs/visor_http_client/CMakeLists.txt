message(STATUS "Visor HTTP Client Library")

find_package(CURL REQUIRED)
find_package(uvw REQUIRED)
find_package(httplib REQUIRED)
find_package(Catch2 REQUIRED)

add_library(VisorHttpClient STATIC HttpClient.cpp)
target_include_directories(VisorHttpClient PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(VisorHttpClient PUBLIC CURL::libcurl uvw::uvw)

add_executable(unit-tests-visor-http-client test_http_client.cpp)
target_link_libraries(unit-tests-visor-http-client PRIVATE VisorHttpClient Catch2::Catch2WithMain httplib::httplib)
add_test(NAME unit-tests-visor-http-client COMMAND unit-tests-visor-http-client)
