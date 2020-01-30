# Install config file
install (
    DIRECTORY snort/dns-firewall
    DESTINATION
        ${CMAKE_INSTALL_FULL_SYSCONFDIR}/snort
)
