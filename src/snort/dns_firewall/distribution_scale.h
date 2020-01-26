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

#ifndef SNORT_DNS_FIREWALL_DISTRIBUTION_SCALE_H
#define SNORT_DNS_FIREWALL_DISTRIBUTION_SCALE_H

#include <string>
#include <vector>

namespace snort { namespace dns_firewall {

enum DistributionScale
{
    LINEAR,
    LOG
};

}} // namespace snort::dns_firewall

#endif // SNORT_DNS_FIREWALL_DISTRIBUTION_SCALE_H
