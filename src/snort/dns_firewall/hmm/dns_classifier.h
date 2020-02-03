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

#ifndef SNORT_DNS_FIREWALL_HMM_DNS_CLASSIFIER_H
#define SNORT_DNS_FIREWALL_HMM_DNS_CLASSIFIER_H

#include "smart_hmm.h"
#include <armadillo>
#include <cmath>
#include <string>

namespace snort { namespace dns_firewall { namespace hmm {

class DnsClassifier
{
  private:
    scientific::ml::Hmm<char, std::string> hmm;

  private:
  public:
    // Default constructor
    DnsClassifier( unsigned window_width, unsigned dist_bins ) noexcept;

    // Learn classifier with one DNS domain
    void learn( const std::string& ) noexcept;
    // Classify DNS domain
    double classify( const std::string& ) noexcept;
};

}}} // namespace snort::dns_firewall::hmm

#endif // SNORT_DNS_FIREWALL_HMM_DNS_CLASSIFIER_H
