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

#ifndef SNORT_DNS_FIREWALL_TIMEFRAME_DNS_CLASSIFIER_H
#define SNORT_DNS_FIREWALL_TIMEFRAME_DNS_CLASSIFIER_H

#include <cmath>
#include <config.h>
#include <ctime>
#include <queue>
#include <string>

namespace snort { namespace dns_firewall { namespace timeframe {

class DnsClassifier
{
  public:
    enum Classification
    {
        VALID,
        INVALID
    };
    struct DomainTimestamp
    {
        std::string domain;
        time_t unix_timestamp;
        DomainTimestamp( const std::string& domain, time_t unix_timestamp )
            : domain( domain )
            , unix_timestamp( unix_timestamp )
        {
        }
    };

  private:
    snort::dns_firewall::Config options;
    std::queue<DomainTimestamp> timestamps;

    void pop_old();

  public:
    explicit DnsClassifier( const snort::dns_firewall::Config& );
    Classification insert( const std::string& );
    unsigned get_current_queries() const;
};

}}} // namespace snort::dns_firewall::timeframe

#endif // SNORT_DNS_FIREWALL_TIMEFRAME_DNS_CLASSIFIER_H
