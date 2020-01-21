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

add_library (
    dnsfirewall MODULE
        snort/dns_firewall/config.cc
        snort/dns_firewall/dns_codec.cc
        snort/dns_firewall/ips_option.cc
        snort/dns_firewall/model.cc
        snort/dns_firewall/module.cc
        snort/dns_firewall/plugin.cc
        snort/dns_firewall/entropy/dns_classifier.cc
        snort/dns_firewall/hmm/dns_classifier.cc
)
target_link_libraries(
    dnsfirewall
    armadillo
    yaml-cpp
)
install (
    TARGETS dnsfirewall
    LIBRARY DESTINATION "lib64/snort/${CMAKE_PROJECT_NAME}"
)

add_executable(
    snort3trainer
        snort/dns_firewall/trainer/config.cc
        snort/dns_firewall/trainer/main.cc
        snort/dns_firewall/trainer/entropy/line_processor.cc
        snort/dns_firewall/trainer/hmm/line_processor.cc
)
target_link_libraries(
    snort3trainer
    armadillo
    yaml-cpp
)
install (
    TARGETS snort3trainer
    RUNTIME DESTINATION "lib64/snort/${CMAKE_PROJECT_NAME}"
)
install (
    FILES config.yaml
    DESTINATION "/etc/snort/dns-firewall"
)
