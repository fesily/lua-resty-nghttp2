cmake_minimum_required(VERSION 3.21)
set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake" ${CMAKE_MODULE_PATH})

project(resty_nghttp2 VERSION 1.0.0)

option(ENABLE_HTTPS "enable https support" OFF)
option(TESTS "test" OFF)
option(SANITIZE_ADDRESS "enable sanitize address" OFF)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

if(CMAKE_C_COMPILER_ID MATCHES "GNU" OR CMAKE_C_COMPILER_ID MATCHES "Clang")
    set(HINT_NORETURN       "__attribute__((noreturn))")
else()
    set(HINT_NORETURN)
endif()

# Checks for header files.
include(CheckIncludeFile)
check_include_file("arpa/inet.h"    HAVE_ARPA_INET_H)
check_include_file("fcntl.h"        HAVE_FCNTL_H)
check_include_file("inttypes.h"     HAVE_INTTYPES_H)
check_include_file("limits.h"       HAVE_LIMITS_H)
check_include_file("netdb.h"        HAVE_NETDB_H)
check_include_file("netinet/in.h"   HAVE_NETINET_IN_H)
check_include_file("pwd.h"          HAVE_PWD_H)
check_include_file("sys/socket.h"   HAVE_SYS_SOCKET_H)
check_include_file("sys/time.h"     HAVE_SYS_TIME_H)
check_include_file("syslog.h"       HAVE_SYSLOG_H)
check_include_file("time.h"         HAVE_TIME_H)
check_include_file("unistd.h"       HAVE_UNISTD_H)

include(CheckTypeSize)
# Checks for typedefs, structures, and compiler characteristics.
# AC_TYPE_SIZE_T
check_type_size("ssize_t" SIZEOF_SSIZE_T)
if(SIZEOF_SSIZE_T STREQUAL "")
    # ssize_t is a signed type in POSIX storing at least -1.
    # Set it to "int" to match the behavior of AC_TYPE_SSIZE_T (autotools).
    set(ssize_t int)
endif()
# AC_TYPE_UINT8_T
# AC_TYPE_UINT16_T
# AC_TYPE_UINT32_T
# AC_TYPE_UINT64_T
# AC_TYPE_INT8_T
# AC_TYPE_INT16_T
# AC_TYPE_INT32_T
# AC_TYPE_INT64_T
# AC_TYPE_OFF_T
# AC_TYPE_PID_T
# AC_TYPE_UID_T
# XXX To support inline for crappy compilers, see https://cmake.org/Wiki/CMakeTestInline
# AC_C_INLINE
# XXX is AC_SYS_LARGEFILE still needed for modern systems?
# add_definitions(-D_FILE_OFFSET_BITS=64)

include(CheckStructHasMember)
check_struct_has_member("struct tm" tm_gmtoff time.h HAVE_STRUCT_TM_TM_GMTOFF)

# Check size of pointer to decide we need 8 bytes alignment adjustment.
check_type_size("int *"   SIZEOF_INT_P)
check_type_size("time_t"  SIZEOF_TIME_T)

# Checks for library functions.
include(CheckFunctionExists)
check_function_exists(_Exit     HAVE__EXIT)
check_function_exists(accept4   HAVE_ACCEPT4)
check_function_exists(mkostemp  HAVE_MKOSTEMP)

include(CheckSymbolExists)
# XXX does this correctly detect initgroups (un)availability on cygwin?
check_symbol_exists(initgroups grp.h HAVE_DECL_INITGROUPS)
if(NOT HAVE_DECL_INITGROUPS AND HAVE_UNISTD_H)
    # FreeBSD declares initgroups() in unistd.h
    check_symbol_exists(initgroups unistd.h HAVE_DECL_INITGROUPS2)
    if(HAVE_DECL_INITGROUPS2)
        set(HAVE_DECL_INITGROUPS 1)
    endif()
endif()

add_definitions(-DHAVE_CONFIG_H)
configure_file(cmakeconfig.h.in config.h)
include_directories(
        "${CMAKE_CURRENT_BINARY_DIR}" # for config.h
)

find_package(Libnghttp2 REQUIRED)
find_package(LuaJIT REQUIRED)

set(CPM_DOWNLOAD_VERSION 0.36.0)
set(CPM_DOWNLOAD_LOCATION "${CMAKE_BINARY_DIR}/cmake/CPM_${CPM_DOWNLOAD_VERSION}.cmake")

if(NOT (EXISTS ${CPM_DOWNLOAD_LOCATION}))
    message(STATUS "Downloading CPM.cmake")
    file(DOWNLOAD https://github.com/TheLartians/CPM.cmake/releases/download/v${CPM_DOWNLOAD_VERSION}/CPM.cmake ${CPM_DOWNLOAD_LOCATION})
endif()

include(${CPM_DOWNLOAD_LOCATION})

if (SANITIZE_ADDRESS)
    add_compile_options(-fsanitize=address)
    add_link_options(-fsanitize=address)
endif()

set(CMAKE_VERBOSE_MAKEFILE ON)
set(CMAKE_CXX_STANDARD 20)

cmake_path(GET LIBNGHTTP2_LIBRARY PARENT_PATH LIBNGHTTP2_LIBRARY_DIRS)
cmake_path(GET LUAJIT_LIBRARY PARENT_PATH LUAJIT_LIBRARY_DIRS)

set(CMAKE_INSTALL_RPATH "${LIBNGHTTP2_LIBRARY_DIRS}:${LUAJIT_LIBRARY_DIRS}")
set(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)

file(GLOB SOURCES
        src/*.cpp)

add_library(resty_nghttp2 SHARED ${SOURCES})

target_include_directories(resty_nghttp2 PRIVATE ${LUAJIT_INCLUDE_DIR} ${LIBNGHTTP2_INCLUDE_DIR})

target_link_libraries(resty_nghttp2 PRIVATE ${LIBNGHTTP2_LIBRARY} ${LUAJIT_LIBRARIES})


if (TESTS)
    add_subdirectory(tests)
endif ()

if (LUA_CPATH)
    set(CMAKE_INSTALL_LIBDIR ${LUA_CPATH})
endif()

install(TARGETS resty_nghttp2
        ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
        LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
        RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}")

if (LUA_PATH)
    install(DIRECTORY lib/resty DESTINATION ${LUA_PATH})
endif()