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
#include "ips_option.h"
#include <profiler/profiler.h>

namespace snort
{
namespace dns_firewall
{

static const Parameter module_params[] = {
    { "enabled", Parameter::PT_BOOL, nullptr, nullptr, "DNS firewall enabled" },
    { "message", Parameter::PT_STRING, nullptr, nullptr, "DNS message" },
    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

Module::Module()
    : snort::Module( module_name, module_help, module_params )
{
}

bool Module::begin( const char*, int, SnortConfig* )
{
    return true;
}

bool Module::set( const char*, Value& v, SnortConfig* )
{
    if( v.is( "enabled" ) ) {
        if( v.get_bool() ) {
            std::cout << "dns_firewall: enabled = true" << std::endl;
        } else {
            std::cout << "dns_firewall: enabled = false" << std::endl;
        }
    } else if( v.is( "message" ) ) {
        std::cout << "dns_firewall: message = " << v.get_string() << std::endl;
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

} // namespace dns_firewall
} // namespace snort
