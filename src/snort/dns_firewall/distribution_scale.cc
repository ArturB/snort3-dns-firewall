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

#include "distribution_scale.h"

namespace snort { namespace dns_firewall {

std::ostream& operator<<( std::ostream& os, const DistributionScale& ds )
{
    if( ds == DistributionScale::LINEAR ) {
        os << "linear";
    }
    if( ds == DistributionScale::LOG ) {
        os << "log";
    }
    return os;
}

}} // namespace snort::dns_firewall
