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

} // namespace dns_firewall
} // namespace snort
