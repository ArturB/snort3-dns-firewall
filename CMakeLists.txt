# **********************************************************************
# Copyright (c) Artur M. Brodzki 2019-2020. All rights reserved.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# **********************************************************************

cmake_minimum_required ( VERSION 3.4.3 )

project( dns-firewall CXX C )
set (VERSION_MAJOR 1)
set (VERSION_MINOR 0)
set (VERSION_PATCH 0)

set (CMAKE_CXX_STANDARD 11)
set (CMAKE_CXX_STANDARD_REQUIRED ON)

# Necessary includes
set(CMAKE_MODULE_PATH
    ${CMAKE_MODULE_PATH}
    ${CMAKE_SOURCE_DIR}/cmake
)
include(CPack)
include(CheckCXXCompilerFlag)
include(RequireLibrary)

# Check binary dependencies
require_library(openblas "")
require_library(armadillo "")
require_library(yaml-cpp "")

# Debug and release build
option ( ENABLE_DEBUG "Enable debugging options (bugreports and developers only)" OFF )
option ( ENABLE_RELEASE "Enable compiler -O3 optimization flags" ON )

set( CMAKE_CXX_FLAGS "-fPIC " )
if ( ENABLE_DEBUG )
    set( CMAKE_BUILD_TYPE "DEBUG" )
    string ( APPEND CMAKE_CXX_FLAGS "-g -DDEBUG " )
else ( ENABLE_DEBUG )
    string ( APPEND CMAKE_CXX_FLAGS "-DNDEBUG " )
endif ( ENABLE_DEBUG )

if ( ENABLE_RELEASE )
    set( CMAKE_BUILD_TYPE "RELEASE" )
    string ( APPEND CMAKE_CXX_FLAGS "-O3 " )
endif ( ENABLE_RELEASE )

# Process src dir
add_subdirectory ( src )
# Process etc dir
add_subdirectory( etc )

# Output dirs
set(CMAKE_INSTALL_PREFIX "/usr/local")
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)

# CPack configuration
set (CPACK_GENERATOR TGZ)
set (CPACK_PACKAGE_NAME "dns-firewall")
set (CPACK_PACKAGE_VENDOR "Artur M. Brodzki")
set (CPACK_PACKAGE_VERSION_MAJOR "${VERSION_MAJOR}")
set (CPACK_PACKAGE_VERSION_MINOR "${VERSION_MINOR}")
set (CPACK_PACKAGE_VERSION_PATCH "${VERSION_PATCH}")
set (CPACK_PACKAGE_INSTALL_DIRECTORY "dist")
set (CPACK_RESOURCE_FILE_LICENSE "${CMAKE_SOURCE_DIR}/LICENSE")
set (CPACK_SOURCE_PACKAGE_FILE_NAME "${CPACK_PACKAGE_NAME}")
set (CPACK_SOURCE_IGNORE_FILES "${CMAKE_BINARY_DIR}/*")
set (CPACK_SOURCE_GENERATOR TGZ)

# Print configuration flags
message("
-------------------------------------------------------

Build type: ${CMAKE_BUILD_TYPE}

Build output options:
    ARCH_OUT:  ${CMAKE_ARCHIVE_OUTPUT_DIRECTORY}
    LIBR_OUT:  ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}
    RUNT_OUT:  ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}

Install options:
    RUNT_DIR:  ${CMAKE_INSTALL_PREFIX}/bin/${CMAKE_PROJECT_NAME}
    LIBR_DIR:  ${CMAKE_INSTALL_PREFIX}/lib64/snort/${CMAKE_PROJECT_NAME}
    INCL_DIR:  ${CMAKE_INSTALL_PREFIX}/include/snort/${CMAKE_PROJECT_NAME}

Compiler options:
    CXX:            ${CMAKE_CXX_COMPILER}
    CXXFLAGS:       ${CMAKE_CXX_FLAGS}
")
