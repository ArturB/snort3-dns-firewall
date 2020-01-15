cmake_minimum_required ( VERSION 3.4.3 )
project ( snort_extra CXX )

set (CMAKE_CXX_STANDARD 11)
set (CMAKE_CXX_STANDARD_REQUIRED ON)
set (CMAKE_CXX_EXTENSIONS OFF)

include ( FindPkgConfig )
pkg_search_module ( SNORT3 REQUIRED snort>=3 )

add_library (
    dns-firewall MODULE
    dns-firewall.cc
)
set_target_properties (
    dns-firewall
    PROPERTIES
        PREFIX ""
)
target_include_directories (
    dns-firewall PUBLIC
    ${SNORT3_INCLUDE_DIRS}
)
install (
    TARGETS dns-firewall
    LIBRARY
        DESTINATION "${CMAKE_INSTALL_LIBDIR}/${CMAKE_PROJECT_NAME}/dns-firewall"
)
