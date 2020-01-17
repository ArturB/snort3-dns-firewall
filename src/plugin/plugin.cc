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

#include "module.h"
#include "option.h"
#include <protocols/packet.h>

using namespace snort;

static Module* mod_ctor()
{
    return new DnsFirewall::Module;
}

static void mod_dtor( Module* m )
{
    delete m;
}

static IpsOption* option_ctor( Module* p, OptTreeNode* )
{
    DnsFirewall::Module* m = (DnsFirewall::Module*) p;
    return new DnsFirewall::Option( m->config_ );
}

static void option_dtor( IpsOption* p )
{
    delete p;
}

static const IpsApi dns_firewall_api = { { PT_IPS_OPTION, sizeof( IpsApi ), IPSAPI_VERSION, 0,
                                           API_RESERVED, API_OPTIONS, DnsFirewall::module_name,
                                           DnsFirewall::module_help, mod_ctor, mod_dtor },
                                         OPT_TYPE_DETECTION,
                                         1,
                                         PROTO_BIT__TCP,
                                         nullptr, // pinit
                                         nullptr, // pterm
                                         nullptr, // tinit
                                         nullptr, // tterm
                                         option_ctor,
                                         option_dtor,
                                         nullptr };

SO_PUBLIC const BaseApi* snort_plugins[] = { &dns_firewall_api.base, nullptr };
