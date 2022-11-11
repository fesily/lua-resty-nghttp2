include_directories(${CMAKE_SOURCE_DIR}/src)

find_package(Catch2 CONFIG REQUIRED)

file(GLOB SOURCES
        test_*.cpp)

add_executable(resty_nghttp2_test ${SOURCES})

target_link_libraries(resty_nghttp2_test PRIVATE c++ resty_nghttp2)
target_link_libraries(resty_nghttp2_test PRIVATE Catch2::Catch2 Catch2::Catch2WithMain)
