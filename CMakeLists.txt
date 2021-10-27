#[[  This file is part of nvlax.

     nvlax is free software: you can redistribute it and/or modify
     it under the terms of the GNU General Public License as published by
     the Free Software Foundation, either version 3 of the License, or
     (at your option) any later version.

     THIS SOFTWARE IS PROVIDED 'AS-IS', WITHOUT ANY EXPRESS
     OR IMPLIED WARRANTY. IN NO EVENT WILL THE AUTHORS BE HELD
     LIABLE FOR ANY DAMAGES ARISING FROM THE USE OF THIS SOFTWARE.  #]]

cmake_minimum_required(VERSION 3.21)

project(nvlax CXX)

include(cmake/FetchCPM.cmake)

CPMAddPackage("gh:zyantific/zydis#master")

CPMAddPackage(
        NAME LIEF
        GIT_TAG master
        GITHUB_REPOSITORY lief-project/LIEF
        DOWNLOAD_ONLY YES
)

if (LIEF_ADDED)
    list(APPEND CMAKE_MODULE_PATH ${LIEF_SOURCE_DIR}/share/LIEF/cmake)
    include(FindLIEF)
    find_package(LIEF REQUIRED COMPONENTS STATIC)
endif()

add_executable(nvlax_encode
        src/common.cc
        src/lax_encode.cc
)

add_executable(nvlax_fbc
        src/common.cc
        src/lax_fbc.cc
)

target_compile_features(nvlax_encode PRIVATE cxx_std_17)
target_compile_features(nvlax_fbc PRIVATE cxx_std_17)
target_link_libraries(nvlax_encode PRIVATE Zydis LIEF)
target_link_libraries(nvlax_fbc PRIVATE Zydis LIEF)

install(TARGETS nvlax_encode nvlax_fbc)
