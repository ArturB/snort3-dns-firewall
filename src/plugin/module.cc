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
#include "option.h"
#include "profiler/profiler.h"

namespace snort
{
namespace DnsFirewall
{

Module::Module()
    : snort::Module( module_name, module_help, module_params )
{
}

bool Module::begin( const char*, int, SnortConfig* )
{
    std::cout << "dns_firewall: begin" << std::endl;
    return true;
}

bool Module::set( const char*, Value& v, SnortConfig* )
{
    if( v.is( "enabled" ) ) {
        if( v.get_bool() ) {
            std::cout << "dns_firewall: enabled = true" << std::endl;
            config_.enabled_ = true;
        } else {
            std::cout << "dns_firewall: enabled = false" << std::endl;
            config_.enabled_ = false;
        }
    } else if( v.is( "message" ) ) {
        config_.message_ = v.get_string();
        std::cout << "dns_firewall: message = " << config_.message_ << std::endl;
    } else {
        return false;
    }

    return true;
}

bool Module::end( const char*, int, SnortConfig* )
{
    return true;
}

ProfileStats* Module::get_profile() const
{
    return &dns_tunnel_perf_stats;
}

Module::Usage Module::get_usage() const
{
    return DETECT;
}

} // namespace DnsFirewall
} // namespace snort
