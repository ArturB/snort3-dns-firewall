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

#ifndef SNORT_DNS_FIREWALL_ENTROPY_DNS_CLASSIFIER_H
#define SNORT_DNS_FIREWALL_ENTROPY_DNS_CLASSIFIER_H

namespace snort
{
namespace dns_firewall
{
namespace entropy
{

class DnsClassifier
{
//  private:
//     class FifoWithMaxSize
//     {
//      public:
//         unsigned max_size;
//         std::queue<std::string> fifo;
//     }

//     snort::dns_classifier::Config config;
//     snort::dns_classifier::Model model;
//     std::vector<DnsClassifier::FifoWithMaxSize> fifos;

//  public:
//     DnsClassifier( const snort::dns_firewall::Config&, const snort::dns_firewall::Model& );
//     double dns_metric( const std::string& );
};

} // namespace entropy
} // namespace dns_firewall
} // namespace snort

#endif // SNORT_DNS_FIREWALL_ENTROPY_DNS_CLASSIFIER_H
