// **********************************************************************
// Copyright (c) Artur M. Brodzki 2019-2020. All rights reserved.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
// **********************************************************************

#include "module.h"
#include "config.h"
#include "ips_option.h"
#include <fstream>
#include <profiler/profiler.h>
#include <unistd.h>

namespace snort { namespace dns_firewall {

static const Parameter module_params[] = {
    { "config_filename",
      Parameter::PT_STRING,
      nullptr,
      nullptr,
      "DNS firewall configuration file path" },
    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

Module::Module()
    : snort::Module( module_name, module_help, module_params ) {
}

bool Module::begin( const char*, int, SnortConfig* ) {
    return true;
}

bool Module::set( const char*, Value& v, SnortConfig* ) {
    if( v.is( "config_filename" ) ) {
        config_filename = v.get_string();
        std::cout << "[DNS Firewall] Config file path: " << config_filename << std::endl;
        if( FILE* file = fopen( config_filename.c_str(), "r" ) ) {
            fclose( file );
            return true;
        } else {
            std::cout << "[DNS Firewall] Could not open config file!" << std::endl;
            return false;
        }
    } else {
        std::cout << "[DNS Firewall] Config file not specified!" << std::endl;
        return false;
    }
}

bool Module::end( const char*, int, SnortConfig* ) {
    return true;
}

ProfileStats* Module::get_profile() const {
    return &dns_tunnel_perf_stats;
}

Module::Usage Module::get_usage() const {
    return DETECT;
}

}} // namespace snort::dns_firewall
