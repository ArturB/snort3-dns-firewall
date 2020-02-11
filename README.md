# snort3-dns-firewall
Open source DNS Firewall implemented as plugin for Snort 3 IDS/IPS system. 

## Compilation
Firewall is implemented as plugin for Snort 3, so you have to install Snort 3 itself before. The code repository is available [here](https://github.com/snort3/snort3), but installation from source is complicated and not recommended. I've prepared precompiled binary packages for various distribution, which can be found [here](https://github.com/ArturB/snort3-precompiled). 

After installing Snort binaries, you have to install also development header files for Snort libDAQ library. Please install it from source, downloading code from [repository](https://github.com/snort3/libdaq). 

Compilation of the plugin itself using cmake:
```
./configure_cmake.sh && ./install.sh
```
However, numerous runtime dependencies must be installed first:
- [OpenBLAS](https://www.openblas.net/), [OpenMP](https://www.openmp.org/) and [yaml-cpp](https://github.com/jbeder/yaml-cpp): please install them as binary packages for your distribution, eg. for Debian-based system:
``` 
sudo apt install libopenblas-dev libomp-dev libyaml-cpp-dev
```
for RPM-based systems:
```
sudo dnf install openblas-devel libomp-devel yaml-cpp-devel
```
or for OpenSUSE:
```
sudo zypper install openblas-devel libomp-devel yaml-cpp-devel
```
- [armadillo](https://github.com/conradsnicta/armadillo), please install it from source using instruction from the [code repository](https://github.com/conradsnicta/armadillo).

# Configuration
The firewall is installed into */usr/local* by default, with trainer executable going into *<INSTALL_PREFIX>/bin/snort/dns-firewall*, plugin SO object going into *l<INSTALL_PREFIX>/ib64/snort/dns-firewall* (or <INSTALL_PREFIX>/lib/<YOUR_ARCHITECTURE_DIR>/snort/dns-firewall* on Debian-based systems) and config files going into *<INSTALL_PREFIX>/etc/snort/dns-firewall*. 

The firewall consists of two main binaries:
- *bin/snort/dns-firewall/dfw3trainer*, which is used to generate ML model file from user-provided DNS logs. Examples of big DNS queries dataset is available to download [here](https://www.brodzki.org/packed-rb.log.gz) and [here](https://www.brodzki.org/packed-ccr.log.gz). Simply run the executable from command line, to print help and available command-line options. 

- *lib64/snort/dns-firewall/libsnort3dfw.so*, which is actual Snort plugin binary. The path to it must be provided to Snort during runtime. 

Both plugin and trainer have numerous options and flags, and are configured by unified YAML configuration file, located at *<INSTALL_PREFIX>/etc/snort/dns-firewall/config.yaml*. Please review the contents of that file to examine available options. 

# Running 
Snort can be started in offline mode (reading data from PCAP file and generating output logs) or in inline mode (sitting between your host and gateway and examining network traffic in real-time). 
