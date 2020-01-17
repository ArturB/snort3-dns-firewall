// **********************************************************************
// Copyright (c) <AUTHOR_NAME> 2019-2020. All rights reserved.
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

#include "option.h"

namespace snort
{
namespace DnsFirewall
{

Option::Option( const Config& config )
    : config_( config )
    , IpsOption( module_name )
{
}

uint32_t Option::hash() const
{
    return 3984583;
}

bool Option::operator==( const Option& operand2 ) const
{
    return config_ == operand2.config_;
}

IpsOption::EvalStatus Option::eval( Cursor&, Packet* p )
{
    if( config_.enabled_ ) {
        std::cout << config_.message_ << std::endl;
        return MATCH;
    } else {
        return NO_MATCH;
    }
}

} // namespace DnsFirewall
} // namespace snort
