cmake_minimum_required(VERSION 3.21)

project(resty_nghttp2 VERSION 1.0.0)

option(ENABLE_HTTPS "enable https support" OFF)
option(TESTS "test" OFF)
option(SANITIZE_ADDRESS "enable sanitize address" OFF)

find_package(OpenSSL REQUIRED)
find_package(Boost REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(nghttp2_asio REQUIRED IMPORTED_TARGET libnghttp2_asio)

set(CPM_DOWNLOAD_VERSION 0.36.0)
set(CPM_DOWNLOAD_LOCATION "${CMAKE_BINARY_DIR}/cmake/CPM_${CPM_DOWNLOAD_VERSION}.cmake")

if(NOT (EXISTS ${CPM_DOWNLOAD_LOCATION}))
    message(STATUS "Downloading CPM.cmake")
    file(DOWNLOAD https://github.com/TheLartians/CPM.cmake/releases/download/v${CPM_DOWNLOAD_VERSION}/CPM.cmake ${CPM_DOWNLOAD_LOCATION})
endif()

include(${CPM_DOWNLOAD_LOCATION})

CPMAddPackage(name nghttp2_asio GITHUB_REPOSITORY fesily/nghttp2-asio GIT_TAG af3405e5869cd0b63658d63694a6ae757da99951)


if (SANITIZE_ADDRESS)
    add_compile_options(-fsanitize=address)
    add_link_options(-fsanitize=address)
endif()

set(CMAKE_VERBOSE_MAKEFILE ON)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_VISIBILITY_PRESET hidden)
set(CMAKE_C_VISIBILITY_PRESET hidden)

file(GLOB SOURCES
        src/*.cpp)

add_library(resty_nghttp2 SHARED ${SOURCES})

set_target_properties(resty_nghttp2 PROPERTIES VERSION ${PROJECT_VERSION} SOVERSION ${PROJECT_VERSION_MAJOR})

target_include_directories(resty_nghttp2 PRIVATE ${OpenSSL_INCLUDE_DIR} ${Boost_INCLUDE_DIR})

#set(CMAKE_SHARED_LINKER_FLAGS  "-ldl -rdynamic")
target_link_libraries(resty_nghttp2 PRIVATE c++ PkgConfig::nghttp2_asio ${OPENSSL_LIBRARIES})

if (TESTS)
    add_subdirectory(tests)
endif ()

if (LUA_CPATH)
    install(TARGETS resty_nghttp2 LIBRARY DESTINATION ${LUA_CPATH} NAMELINK_SKIP)
endif()

if (LUA_PATH)
    install(DIRECTORY lib/resty DESTINATION ${LUA_PATH})
endif()