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

#include "dns_classifier.h"
#include "model.h"
#include <regex>

namespace snort { namespace dns_firewall {

DnsClassifier::DnsClassifier( const Config& config )
    : options( config )
{
    Model model;
    model.load( options.model_file );

    // Initialize blacklist
    std::ifstream blacklist_file( options.blacklist );
    std::string line;
    while( std::getline( blacklist_file, line ) ) {
        blacklist.push_back( line );
    }
    blacklist_file.close();
    // Initialize whitelist
    std::ifstream whitelist_file( options.whitelist );
    while( getline( whitelist_file, line ) ) {
        whitelist.push_back( line );
    }
    whitelist_file.close();
    // Initialize entropy clasifiers
    for( auto it = model.entropy_distribution.begin(); it != model.entropy_distribution.end();
         ++it ) {
        entropy_classifiers.push_back( entropy::DnsClassifier( it->first, it->second.size() ) );
        entropy_classifiers.back().set_entropy_distribution(
          it->second, 1000000, DistributionScale::LOG );
    }
}

Classification DnsClassifier::classify_question( const std::string& domain )
{
    // Blacklist check
    for( auto it = blacklist.begin(); it != blacklist.end(); ++it ) {
        if( std::regex_match( domain, std::regex( ".*" + *it ) ) ) {
            return Classification( domain, Classification::Note::BLACKLIST, 0 );
        }
    }

    // Whitelist check
    for( auto it = whitelist.begin(); it != whitelist.end(); ++it ) {
        if( std::regex_match( domain, std::regex( ".*" + *it ) ) ) {
            return Classification( domain, Classification::Note::WHITELIST, 0 );
        }
    }

    // Min length check
    if( domain.size() < options.length.min_length ) {
        return Classification( domain, Classification::Note::MIN_LENGTH, 0 );
    }

    double entropy_score = 0;
    // Entropy score
    for( auto it = entropy_classifiers.begin(); it != entropy_classifiers.end(); ++it ) {
        entropy_score += it->classify( domain );
    }
    entropy_score /= entropy_classifiers.size();

    // Max length penalty
    if( domain.size() > options.length.max_length ) {
        entropy_score -=
          ( domain.size() - options.length.max_length ) * options.length.max_length_penalty;
    }

    return Classification( domain, Classification::Note::SCORE, entropy_score );
}

Classification DnsClassifier::classify( const DnsPacket& dns )
{
    Classification min_cls;
    for( auto it = dns.questions.begin(); it != dns.questions.end(); ++it ) {
        Classification cls = classify_question( it->qname );
        if( cls < min_cls ) {
            min_cls = cls;
        }
    }
    return min_cls;
}

}} // namespace snort::dns_firewall
