cmake_minimum_required(VERSION 3.21)
if (POLICY CMP0048)
    cmake_policy(SET CMP0048 NEW)
endif (POLICY CMP0048)

project(resty_nghttp2 VERSION 1.0.0)

option(ENABLE_HTTPS "enable https support" OFF)
option(TESTS "test" OFF)
option(SANITIZE_ADDRESS "enable sanitize address" OFF)

if (SANITIZE_ADDRESS)
    add_compile_options(-fsanitize=address)
    add_link_options(-fsanitize=address)
endif()

set(CMAKE_VERBOSE_MAKEFILE ON)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_VISIBILITY_PRESET hidden)
set(CMAKE_C_VISIBILITY_PRESET hidden)

#add_compile_options(-fcoroutines-ts -fsanitize=address)
#add_link_options(-fsanitize=address)
#add_compile_options(-fcoroutines-ts)

find_package(OpenSSL REQUIRED)
find_package(Boost REQUIRED)

find_package(PkgConfig REQUIRED)
pkg_check_modules(nghttp2_asio REQUIRED IMPORTED_TARGET libnghttp2_asio)

file(GLOB SOURCES
        src/*.cpp)

add_library(resty_nghttp2 SHARED ${SOURCES})

if (NOT LUA_CPATH)
    set_target_properties(resty_nghttp2 PROPERTIES VERSION ${PROJECT_VERSION} SOVERSION ${PROJECT_VERSION_MAJOR})
endif()

target_include_directories(resty_nghttp2 PRIVATE ${OPENSSL_INCLUDE_DIR} ${Boost_INCLUDE_DIR})

#set(CMAKE_SHARED_LINKER_FLAGS  "-ldl -rdynamic")
target_link_libraries(resty_nghttp2 PRIVATE c++ PkgConfig::nghttp2_asio ${OPENSSL_LIBRARIES})

if (TESTS)
    add_subdirectory(tests)
endif ()

if (LUA_CPATH)
    install(TARGETS resty_nghttp2 DESTINATION ${LUA_CPATH})
endif()

if (LUA_PATH)
    install(DIRECTORY lib/resty DESTINATION ${LUA_PATH})
endif()