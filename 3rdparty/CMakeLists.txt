# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

# libcurl
find_package(openenclave 0.6 REQUIRED CONFIG)
set(BUILD_CURL_EXE OFF CACHE BOOL "" FORCE)
set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
set(HTTP_ONLY ON CACHE BOOL "" FORCE)
set(CURL_DISABLE_COOKIES ON CACHE BOOL "" FORCE)
set(CURL_ZLIB OFF CACHE BOOL "" FORCE)
set(ENABLE_UNIX_SOCKETS OFF CACHE BOOL "" FORCE)
if (CMAKE_BUILD_TYPE STREQUAL Debug)
  set(ENABLE_DEBUG ON CACHE BOOL "" FORCE)
endif()
set(CMAKE_USE_OPENSSL OFF CACHE BOOL "" FORCE)
set(CMAKE_USE_MBEDTLS ON CACHE BOOL "" FORCE)
# Satisfy curl's FindMbedTLS module, mbedtls supplied by oeenclave.
set(MBEDTLS_LIBRARY "" CACHE STRING "" FORCE)
set(MBEDX509_LIBRARY "" CACHE STRING "" FORCE)
set(MBEDCRYPTO_LIBRARY "" CACHE STRING "" FORCE)
set(MBEDTLS_INCLUDE_DIRS "" CACHE STRING "" FORCE)
# Avoid that curl links to dl.
set(HAVE_LIBDL OFF CACHE BOOL "" FORCE)

# Use single-threaded DNS resolution, to avoid pthread symbol resolution issues
set(ENABLE_THREADED_RESOLVER OFF CACHE BOOL "" FORCE)

# Curl believes these symbols are available, they are not
set(HAVE_ALARM OFF CACHE BOOL "" FORCE)
set(HAVE_SIGSETJMP OFF CACHE BOOL "" FORCE)

add_compile_definitions(CURL_DISABLE_NETRC USE_BLOCKING_SOCKETS)
add_subdirectory(curl EXCLUDE_FROM_ALL)
target_link_libraries(libcurl
  openenclave::oecore
  openenclave::oeenclave
  openenclave::oelibc
  openenclave::oelibcxx
  openenclave::oehostsock
  openenclave::oehostresolver
)

set(oe_stubs
  ${CMAKE_CURRENT_SOURCE_DIR}/patches/stubs_undefined.c
)

target_sources(libcurl PRIVATE ${oe_stubs})

set_property(TARGET libcurl PROPERTY POSITION_INDEPENDENT_CODE ON)
