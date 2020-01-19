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

#include "ips_option.h"

namespace snort
{
namespace dns_firewall
{

dns_firewall::IpsOption::IpsOption( const Config& config )
    : config_( config )
    , snort::IpsOption( module_name )
{
}

uint32_t dns_firewall::IpsOption::hash() const
{
    return 3984583;
}

bool dns_firewall::IpsOption::operator==( const dns_firewall::IpsOption& operand2 ) const
{
    return config_ == operand2.config_;
}

snort::IpsOption::EvalStatus dns_firewall::IpsOption::eval( Cursor&, Packet* p )
{
    if( config_.enabled_ ) {
        std::cout << config_.message_ << std::endl;
        return MATCH;
    } else {
        return NO_MATCH;
    }
}

} // namespace dns_firewall
} // namespace snort
