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

#ifndef SNORT_DNS_FIREWALL_DNS_CLASSIFIER_H
#define SNORT_DNS_FIREWALL_DNS_CLASSIFIER_H

#include "classification.h"
#include "config.h"
#include "dns_packet.h"
#include "entropy/dns_classifier.h"
#include "hmm/dns_classifier.h"

namespace snort { namespace dns_firewall {

class DnsClassifier
{
  public:
  private:
    Config options;
    std::vector<std::string> blacklist;
    std::vector<std::string> whitelist;
    std::vector<entropy::DnsClassifier> entropy_classifiers;
    Classification classify_question( const std::string& );

  public:
    explicit DnsClassifier( const Config& );
    Classification classify( const DnsPacket& );
};

}} // namespace snort::dns_firewall

#endif // SNORT_DNS_FIREWALL_DNS_CLASSIFIER_H
