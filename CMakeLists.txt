cmake_minimum_required(VERSION 2.8)
project(noknok C)

set(COMMON_CFLAGS "-Wall -Wextra")
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(COMMON_CFLAGS "${COMMON_CFLAGS} -O0")
else(CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(COMMON_CFLAGS "${COMMON_CFLAGS} -O2 -s")
endif(CMAKE_BUILD_TYPE STREQUAL "Debug")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${COMMON_CFLAGS}")

set(SOURCES
    noknok.c
    ykaes.c
    ykcrc.c
    ykhex.c
    yktoken.c
)

set(HEADERS
    yubikey.h
)

add_executable(noknok ${SOURCES} ${HEADERS})

install(TARGETS noknok DESTINATION ${CMAKE_INSTALL_PREFIX}/bin)
