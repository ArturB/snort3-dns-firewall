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
#include <ostream>

namespace snort { namespace dns_firewall {

struct Config
{
    enum Mode
    {
        SIMPLE,
        LIVE
    };
    struct TimeframeConfig
    {
        unsigned period;
        unsigned max_queries;
        bool operator==( const TimeframeConfig& ) const;
        friend std::ostream& operator<<( std::ostream&, const TimeframeConfig& );
    };
    struct HmmConfig
    {
        unsigned weight;
        bool operator==( const HmmConfig& ) const;
        friend std::ostream& operator<<( std::ostream&, const HmmConfig& );
    };
    struct EntropyConfig
    {
        unsigned weight;
        bool operator==( const EntropyConfig& ) const;
        friend std::ostream& operator<<( std::ostream&, const EntropyConfig& );
    };
    struct LengthConfig
    {
        unsigned min_length;
        unsigned max_length;
        double max_length_penalty;
        bool operator==( const LengthConfig& ) const;
        friend std::ostream& operator<<( std::ostream&, const LengthConfig& );
    };
    struct RejectConfig
    {
        unsigned block_period;
        int threshold;
        unsigned repetitions;
        bool operator==( const RejectConfig& ) const;
        friend std::ostream& operator<<( std::ostream&, const RejectConfig& );
    };

    Mode mode;
    std::string model_file;
    std::string blacklist;
    std::string whitelist;
    TimeframeConfig timeframe;
    HmmConfig hmm;
    EntropyConfig entropy;
    LengthConfig length;
    RejectConfig short_reject;
    RejectConfig long_reject;
    RejectConfig permanent_reject;

    explicit Config( const std::string& );
    bool operator==( const Config& ) const;
    friend std::ostream& operator<<( std::ostream&, const Config& );
};

std::ostream& operator<<( std::ostream&, const Config::Mode& );

}} // namespace snort::dns_firewall

#endif // SNORT_DNS_FIREWALL_CONFIG_H
