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

#include "config.h"

namespace snort
{
namespace dns_firewall
{

Config::Config()
    : enabled_( true )
    , message_( "Default DNS Firewall message!" )
{
}

Config::Config( bool enabled, const std::string& message )
    : enabled_( enabled )
    , message_( message )
{
}

bool Config::operator==( const Config& operand2 ) const
{
    return enabled_ == operand2.enabled_ and message_ == operand2.message_;
}

} // namespace dns_firewall
} // namespace snort
