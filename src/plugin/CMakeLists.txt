add_library (
    dns-firewall MODULE
    config.cc option.cc module.cc plugin.cc
)
target_include_directories (
    dns-firewall PUBLIC
    ${SNORT3_INCLUDE_DIRS}
)
install (
    TARGETS dns-firewall
    LIBRARY DESTINATION "lib64/snort/${CMAKE_PROJECT_NAME}"
)
