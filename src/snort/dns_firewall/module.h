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

#ifndef SNORT_DNS_FIREWALL_MODULE_H
#define SNORT_DNS_FIREWALL_MODULE_H

#include "config.h"
#include "ips_option.h"
#include <framework/module.h>
#include <iostream>
#include <profiler/profiler.h>

namespace snort { namespace dns_firewall {

static THREAD_LOCAL ProfileStats dns_tunnel_perf_stats;

class Module : public snort::Module
{
  public:
    std::string config_filename;

  public:
    Module();

    bool begin( const char*, int, SnortConfig* ) override;
    bool set( const char*, Value& v, SnortConfig* ) override;
    bool end( const char*, int, SnortConfig* ) override;

    ProfileStats* get_profile() const override;
    Usage get_usage() const override;
};

}} // namespace snort::dns_firewall

#endif // SNORT_DNS_FIREWALL_MODULE_H
