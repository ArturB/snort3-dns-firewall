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

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)

include_directories(
    snort/dns_firewall
)

set(LIBRARY_NAME "snort3dfw")
set(TRAINER_NAME "dfw3trainer")
set(TESTING_NAME "testdfw3")

# ******************
# SMART-HMM LIBRARY
# ******************

include_directories(
    scientific/ml
)

# *********************
# PLUGIN SHARED OBJECT
# *********************

add_library (
    ${LIBRARY_NAME} MODULE
        snort/dns_firewall/classification.cc
        snort/dns_firewall/config.cc
        snort/dns_firewall/distribution_scale.cc
        snort/dns_firewall/dns_classifier.cc
        snort/dns_firewall/dns_packet.cc
        snort/dns_firewall/ips_option.cc
        snort/dns_firewall/model.cc
        snort/dns_firewall/module.cc
        snort/dns_firewall/plugin.cc
        snort/dns_firewall/entropy/dns_classifier.cc
        snort/dns_firewall/timeframe/dns_classifier.cc
)
target_link_libraries(
    ${LIBRARY_NAME}
    armadillo
    yaml-cpp
)
install (
    TARGETS ${LIBRARY_NAME}
    LIBRARY DESTINATION
        ${CMAKE_INSTALL_FULL_LIBDIR}/snort/${CMAKE_PROJECT_NAME}
)

# *******************
# TRAINER EXECUTABLE
# *******************

add_executable(
    ${TRAINER_NAME}
        snort/dns_firewall/distribution_scale.cc
        snort/dns_firewall/model.cc
        snort/dns_firewall/entropy/dns_classifier.cc
        snort/dns_firewall/trainer/config.cc
        snort/dns_firewall/trainer/main.cc
)
target_link_libraries(
    ${TRAINER_NAME}
    armadillo
    omp
    yaml-cpp
)
install (
    TARGETS ${TRAINER_NAME}
    RUNTIME DESTINATION
        ${CMAKE_INSTALL_FULL_BINDIR}/snort/${CMAKE_PROJECT_NAME}
)

# *******************
# TESTING EXECUTABLE
# *******************

add_executable(
    ${TESTING_NAME}
        snort/dns_firewall/classification.cc
        snort/dns_firewall/config.cc
        snort/dns_firewall/dns_classifier.cc
        snort/dns_firewall/dns_packet.cc
        snort/dns_firewall/model.cc
        snort/dns_firewall/test/main.cc
        snort/dns_firewall/entropy/dns_classifier.cc
        snort/dns_firewall/timeframe/dns_classifier.cc
)
target_link_libraries(
    ${TESTING_NAME}
    armadillo
    omp
    yaml-cpp
)
install (
    TARGETS ${TESTING_NAME}
    RUNTIME DESTINATION
        ${CMAKE_INSTALL_FULL_BINDIR}/snort/${CMAKE_PROJECT_NAME}
)