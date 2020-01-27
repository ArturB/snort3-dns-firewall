# Install trainer config file
install (
    FILES
        snort/dns-firewall/config.yaml
        snort/dns-firewall/basic.snort3model
        snort/dns-firewall/blacklist.snort3model
        snort/dns-firewall/whitelist.snort3model
    DESTINATION "/etc/snort/${CMAKE_PROJECT_NAME}"
)
