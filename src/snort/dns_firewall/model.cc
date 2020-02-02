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

#include "model.h"
#include <cereal/archives/binary.hpp>
#include <cereal/types/string.hpp>
#include <cereal/types/unordered_map.hpp>
#include <cereal/types/vector.hpp>
#include <fstream>

namespace snort { namespace dns_firewall {

Model::Model()
    : query_max_length( 0 )
    , max_length_penalty( 0 )
    , bins( 0 )
{
}

template<class Archive>
void Model::serialize( Archive& archive )
{
    archive( query_max_length, max_length_penalty, bins, entropy_distribution );
}

void Model::save_to_file( std::string filename )
{
    std::ofstream fs( filename );
    cereal::BinaryOutputArchive oarchive( fs );
    oarchive( *this );
    fs.close();
}

void Model::load_from_file( std::string filename )
{
    std::ifstream fs( filename );
    cereal::BinaryInputArchive iarchive( fs );
    iarchive( *this );
    fs.close();
}

void Model::save_graphs( const std::string& filename_prefix,
                         const std::string& filename_suffix )
{
    for( auto& d: entropy_distribution ) {
        std::ofstream fs( filename_prefix + std::to_string( d.first ) + filename_suffix );
        double i = 1;
        for( auto& val: d.second ) {
            fs << i / d.second.size() << ";" << val << std::endl;
            ++i;
        }
        fs.close();
    }
}

std::ostream& operator<<( std::ostream& os, const Model& model )
{
    os << "[DNS Firewall]  - Entropy window widths: ";
    for( auto& d: model.entropy_distribution ) {
        os << d.first << " ";
    }
    os << std::endl;
    os << "[DNS Firewall]  - Max queries length: " << model.query_max_length << std::endl;
    os << "[DNS Firewall]  - Max-length penalty: " << model.max_length_penalty;
    return os;
}

}} // namespace snort::dns_firewall
