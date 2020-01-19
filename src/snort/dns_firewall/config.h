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

#ifndef SNORT_DNS_FIREWALL_CONFIG_H
#define SNORT_DNS_FIREWALL_CONFIG_H

#include <string>

namespace snort
{
namespace dns_firewall
{

class Config
{
  public:
    bool enabled_;
    std::string message_;

  public:
    Config();
    Config( bool, const std::string& );
    bool operator==( const Config& ) const;
};

} // namespace dns_firewall
} // namespace snort

#endif // SNORT_DNS_FIREWALL_CONFIG_H
