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

#ifndef SNORT_DNS_FIREWALL_TRAINER_CONFIG_H
#define SNORT_DNS_FIREWALL_TRAINER_CONFIG_H

#include "distribution_scale.h"
#include <string>
#include <vector>

namespace snort { namespace dns_firewall { namespace trainer {

struct Config
{
    struct HmmConfig
    {
        unsigned hidden_states;
        bool operator==( const HmmConfig& ) const;
    };
    struct EntropyConfig
    {
        unsigned bins;
        snort::dns_firewall::DistributionScale scale;
        std::vector<unsigned> window_widths;
        bool operator==( const EntropyConfig& ) const;
    };

    std::string dataset;
    std::string model_file;
    int max_lines;
    HmmConfig hmm;
    EntropyConfig entropy;

    explicit Config( const std::string& );
    bool operator==( const Config& ) const;
};

}}} // namespace snort::dns_firewall::trainer

#endif // SNORT_DNS_FIREWALL_TRAINER_CONFIG_H
