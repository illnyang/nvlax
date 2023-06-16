#[[  This file is part of nvlax.

     nvlax is free software: you can redistribute it and/or modify
     it under the terms of the GNU General Public License as published by
     the Free Software Foundation, either version 3 of the License, or
     (at your option) any later version.

     THIS SOFTWARE IS PROVIDED 'AS-IS', WITHOUT ANY EXPRESS
     OR IMPLIED WARRANTY. IN NO EVENT WILL THE AUTHORS BE HELD
     LIABLE FOR ANY DAMAGES ARISING FROM THE USE OF THIS SOFTWARE.  #]]

cmake_minimum_required(VERSION 3.14)

project(nvlax CXX)

include(ExternalProject)
include(cmake/FetchCPM.cmake)

CPMAddPackage("gh:zyantific/zydis#1ba75aeefae37094c7be8eba07ff81d4fe0f1f20")

CPMAddPackage(
        NAME LIEF_SRC
        GIT_TAG b9a5f970b210dbc115c7aaac10e04623bdc08ef8
        GITHUB_REPOSITORY lief-project/LIEF
        DOWNLOAD_ONLY YES
)

if (LIEF_SRC_ADDED)
    set(LIEF_PREFIX       "${CMAKE_CURRENT_BINARY_DIR}/LIEF")
    set(LIEF_INSTALL_DIR  "${LIEF_PREFIX}")
    set(LIEF_INCLUDE_DIRS "${LIEF_PREFIX}/include")

    set(LIEF_LIBRARIES
            "${LIEF_PREFIX}/lib/${CMAKE_STATIC_LIBRARY_PREFIX}LIEF${CMAKE_STATIC_LIBRARY_SUFFIX}"
    )

    set(LIEF_CMAKE_ARGS
            -DCMAKE_INSTALL_PREFIX=<INSTALL_DIR>
            -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
            -DLIEF_DOC=off
            -DLIEF_PYTHON_API=off
            -DLIEF_EXAMPLES=off
            -DCMAKE_CXX_COMPILER=${CMAKE_CXX_COMPILER}
            -DCMAKE_C_COMPILER=${CMAKE_C_COMPILER}
    )

    ExternalProject_Add(LIEF
            PREFIX           "${LIEF_PREFIX}"
            SOURCE_DIR       ${LIEF_SRC_SOURCE_DIR}
            INSTALL_DIR      ${LIEF_INSTALL_DIR}
            CMAKE_ARGS       ${LIEF_CMAKE_ARGS}
            BUILD_BYPRODUCTS ${LIEF_LIBRARIES}
            UPDATE_COMMAND   ""
    )
endif()

message(STATUS "LIEF include directory: ${LIEF_INCLUDE_DIRS}")
message(STATUS "LIEF library: ${LIEF_LIBRARIES}")

CPMAddPackage(
        NAME PPK_ASSERT
        GIT_TAG 833b8b7ea49aea540a49f07ad08bf0bae1faac32
        GITHUB_REPOSITORY gpakosz/PPK_ASSERT
        DOWNLOAD_ONLY YES
)

if (PPK_ASSERT_ADDED)
    add_library(PPK_ASSERT STATIC
            ${PPK_ASSERT_SOURCE_DIR}/src/ppk_assert.cpp
            ${PPK_ASSERT_SOURCE_DIR}/src/ppk_assert.h
    )

    target_compile_definitions(PPK_ASSERT PUBLIC
            -DPPK_ASSERT_ENABLED=1
    )

    target_include_directories(PPK_ASSERT PUBLIC
            $<BUILD_INTERFACE:${PPK_ASSERT_SOURCE_DIR}/src/>
    )
endif()

add_executable(nvlax_encode
        src/common.cc
        src/lax_encode.cc
)

add_executable(nvlax_fbc
        src/common.cc
        src/lax_fbc.cc
)

add_dependencies(nvlax_encode LIEF)
add_dependencies(nvlax_fbc LIEF)

target_compile_features(nvlax_encode PRIVATE cxx_std_17)
target_compile_features(nvlax_fbc PRIVATE cxx_std_17)
target_include_directories(nvlax_encode PRIVATE ${LIEF_INCLUDE_DIRS})
target_include_directories(nvlax_fbc PRIVATE ${LIEF_INCLUDE_DIRS})
target_link_libraries(nvlax_encode PRIVATE Zydis ${LIEF_LIBRARIES} PPK_ASSERT)
target_link_libraries(nvlax_fbc PRIVATE Zydis ${LIEF_LIBRARIES} PPK_ASSERT)

install(TARGETS nvlax_encode nvlax_fbc)
