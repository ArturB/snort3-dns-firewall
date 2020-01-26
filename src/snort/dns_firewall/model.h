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

#ifndef SNORT_DNS_FIREWALL_TRAINER_MODEL_H
#define SNORT_DNS_FIREWALL_TRAINER_MODEL_H

#include <unordered_map>
#include <vector>

namespace snort
{
namespace dns_firewall
{

class Model
{
  private:
    unsigned bins;
    std::unordered_map<unsigned, std::vector<double>> entropy_distribution;

  public:
    Model();
    void save( std::string filename );
    void load( std::string filename );
    void save_graphs( const std::string&, const std::string& = ".csv" );
    unsigned get_bins() const noexcept;
    std::unordered_map<unsigned, std::vector<double>> get_entropy_distribution() const noexcept;
};

} // namespace dns_firewall
} // namespace snort

#endif // SNORT_DNS_FIREWALL_TRAINER_MODEL_H
