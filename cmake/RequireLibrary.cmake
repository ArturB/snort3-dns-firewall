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
