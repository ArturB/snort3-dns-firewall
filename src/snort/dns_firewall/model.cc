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
#include <unordered_map>

namespace snort
{
namespace dns_firewall
{

Model::Model()
    : bins( 0 )
{
}

void Model::save( std::string filename )
{
    std::ofstream fs( filename );
    cereal::BinaryOutputArchive oarchive( fs );
    oarchive( bins, entropy_distribution );
    fs.close();
}

void Model::load( std::string filename )
{
    std::ifstream fs( filename );
    cereal::BinaryInputArchive iarchive( fs );
    iarchive( bins, entropy_distribution );
    fs.close();
}

void Model::save_graphs( const std::string& filename_prefix,
                         const std::string& filename_suffix )
{
    for( auto it = entropy_distribution.begin(); it != entropy_distribution.end(); ++it ) {
        std::ofstream fs( filename_prefix + std::to_string( it->first ) + filename_suffix );
        for( unsigned i = 0; i < it->second.size(); ++i ) {
            fs << it->second[i] << std::endl;
        }
        fs.close();
    }
}

unsigned Model::get_bins() const noexcept
{
    return bins;
}

std::unordered_map<unsigned, std::vector<double>> Model::get_entropy_distribution() const
  noexcept
{
    return entropy_distribution;
}

} // namespace dns_firewall
} // namespace snort
