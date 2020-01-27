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

macro(require_library LIBRARY_NAME SEARCH_LIBRARY_PATH)

    string(APPEND
        ${CMAKE_SYSTEM_LIBRARY_PATH}
        /lib64 /lib /usr/lib64 /usr/lib /usr/local/lib64
    )
    string(APPEND
        ${CMAKE_SYSTEM_LIBRARY_PATH}
        ${SEARCH_LIBRARY_PATH}
    )

    set(${RESULT_VAR} false)
    find_library(${LIBRARY_NAME}_FIND_LIBRARY_OUTPUT
        NAMES ${LIBRARY_NAME}
        PATHS ${CMAKE_SYSTEM_LIBRARY_PATH}
              /lib64 /lib /usr/lib64 /usr/lib /usr/local/lib64
    )

    if(${LIBRARY_NAME}_FIND_LIBRARY_OUTPUT MATCHES NOTFOUND)
        message(STATUS "Check for ${LIBRARY_NAME} library - not found!")
        message(FATAL_ERROR "\nLibrary ${LIBRARY_NAME} not found. Please install it first and then try to run project configuration again.\n")
    else(${LIBRARY_NAME}_FIND_LIBRARY_OUTPUT MATCHES NOTFOUND)
        message(STATUS "Check for ${LIBRARY_NAME} library - found")
    endif(${LIBRARY_NAME}_FIND_LIBRARY_OUTPUT MATCHES NOTFOUND)

endmacro()
