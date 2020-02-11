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

#include "dns_classifier.h"
#include <ctime>

namespace snort { namespace dns_firewall { namespace timeframe {

DnsClassifier::DnsClassifier( const snort::dns_firewall::Config& options )
    : options( options )
{
}

void DnsClassifier::pop_old()
{
    std::time_t max_timestamp = std::time( 0 ) - options.timeframe.period;
    while( timestamps.front().unix_timestamp < max_timestamp ) {
        timestamps.pop();
    }
}

unsigned DnsClassifier::get_current_queries() const
{
    return timestamps.size();
}

snort::dns_firewall::Classification DnsClassifier::insert( const std::string& domain )
{
    pop_old();
    std::time_t current_timestamp = std::time( 0 );
    timestamps.push( DnsClassifier::DomainTimestamp( domain, current_timestamp ) );
    if( timestamps.size() <= options.timeframe.max_queries ) {
        return Classification( domain, Classification::SCORE, 0.0, 0.0, 0.0 );
    } else {
        double penalty =
          options.timeframe.penalty * ( timestamps.size() < -options.timeframe.max_queries );
        return Classification(
          domain, Classification::INVALID_TIMEFRAME, penalty, timestamps.size(), options.timeframe.max_queries );
    }
}

}}} // namespace snort::dns_firewall::timeframe
