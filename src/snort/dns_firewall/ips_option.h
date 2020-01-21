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

#ifndef SNORT_DNS_FIREWALL_OPTION_H
#define SNORT_DNS_FIREWALL_OPTION_H

#include "config.h"
#include <framework/ips_option.h>
#include <iostream>

namespace snort
{
namespace dns_firewall
{

static const char* module_name = "dns_firewall";
static const char* module_help = "alert on suspicious DNS queries activity";

class IpsOption : public snort::IpsOption
{
  private:
    //Config config_;

  public:
    IpsOption( );
    bool operator==( const IpsOption& ) const;

    uint32_t hash() const override;
    EvalStatus eval( Cursor&, Packet* ) override;
};

} // namespace dns_firewall
} // namespace snort

#endif // SNORT_DNS_FIREWALL_IPS_OPTION_H
