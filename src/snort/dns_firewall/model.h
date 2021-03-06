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

#ifndef SNORT_DNS_FIREWALL_MODEL_H
#define SNORT_DNS_FIREWALL_MODEL_H

#include "smart_hmm.h"
#include <string>
#include <unordered_map>
#include <vector>

namespace snort { namespace dns_firewall {

struct Model
{
    unsigned query_max_length;
    double max_length_penalty;
    std::unordered_map<unsigned, std::vector<double>> entropy_distribution;
    unsigned bins;
    scientific::ml::Hmm<char, std::string> hmm;

    Model();

    template<class Archive>
    void serialize( Archive& );

    void save_to_file( std::string filename );
    void load_from_file( std::string filename );
    void save_graphs( const std::string&, const std::string& = ".csv" );

    bool operator==( const Model& ) const;
    friend std::ostream& operator<<( std::ostream&, const Model& );
};

}} // namespace snort::dns_firewall

#endif // SNORT_DNS_FIREWALL_MODEL_H
