cmake_minimum_required(VERSION 3.0)
project(dumptorrent)

set(SOURCE_DUMP dumptorrent.c benc.c benc.h scrapec.c scrapec.h sha1.c sha1.h common.h)
set(SOURCE_SCRAPE scrapec.c scrapec.h benc.c benc.h sha1.c sha1.h common.h)

add_executable(dumptorrent ${SOURCE_DUMP})
add_executable(scrapec ${SOURCE_SCRAPE})

target_compile_definitions(scrapec PUBLIC BUILD_MAIN)
