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
#include "classification.h"
#include "dns_packet.h"
#include "model.h"
#include <regex>

namespace snort { namespace dns_firewall {

DnsClassifier::DnsClassifier( const Config& config )
    : options( config )
    , query_max_length( 256 )
    , max_length_penalty( 0 )
    , timeframe_classifier( config )
{
    Model model;
    model.load( options.model.filename );

    query_max_length   = model.query_max_length;
    max_length_penalty = model.max_length_penalty;

    // Initialize blacklist, if applicable
    if( not options.blacklist.empty() ) {
        std::ifstream blacklist_file( options.blacklist );
        std::string line;
        while( std::getline( blacklist_file, line ) ) {
            blacklist.push_back( line );
        }
        blacklist_file.close();
    }

    // Initialize whitelist, if applicable
    if( not options.whitelist.empty() ) {
        std::ifstream whitelist_file( options.whitelist );
        std::string line;
        while( getline( whitelist_file, line ) ) {
            whitelist.push_back( line );
        }
        whitelist_file.close();
    }

    // Initialize entropy clasifiers
    for( auto& d: model.entropy_distribution ) {
        entropy_classifiers.push_back( entropy::DnsClassifier( d.first, d.second.size() ) );
        entropy_classifiers.back().set_entropy_distribution(
          d.second, options.model.weight, DistributionScale::LOG );
    }
}

Classification DnsClassifier::classify_question( const std::string& domain )
{
    // ****************
    // Blacklist check
    // ****************
    if( std::any_of( blacklist.begin(), blacklist.end(), [&]( auto blacklisted ) {
            return std::regex_match( domain, std::regex( ".*" + blacklisted ) );
        } ) ) {
        return Classification( domain, Classification::Note::BLACKLIST, 0 );
    }

    // ****************
    // Whitelist check
    // ****************
    if( std::any_of( whitelist.begin(), whitelist.end(), [&]( auto whitelisted ) {
            return std::regex_match( domain, std::regex( ".*" + whitelisted ) );
        } ) ) {
        return Classification( domain, Classification::Note::WHITELIST, 0 );
    }

    // ****************
    // Timeframe check
    // ****************
    if( timeframe_classifier.insert( domain ) ==
        timeframe::DnsClassifier::Classification::INVALID ) {
        return Classification( domain,
                               Classification::Note::INVALID_TIMEFRAME,
                               timeframe_classifier.get_current_queries(),
                               options.timeframe.max_queries );
    }

    // ****************
    // HMM CLASSIFIER
    // ****************
    double hmm_score = 0;

    // *******************
    // ENTROPY CLASSIFIER
    // *******************
    double entropy_score = 0;
    if( domain.size() >= options.entropy.min_length ) { // Min length check
        // Average score from each entropy classifier
        for( auto& c: entropy_classifiers ) {
            entropy_score += c.classify( domain );
        }
        entropy_score /= entropy_classifiers.size();
    }

    // *******************
    // TOTAL SCORE
    // *******************
    double score =
      ( options.hmm.weight * hmm_score ) + ( options.entropy.weight * entropy_score ) /
                                             ( options.hmm.weight + options.entropy.weight );

    // *******************
    // MAX LENGTH PENALTY
    // *******************
    if( domain.size() > query_max_length ) {
        score -= ( domain.size() - query_max_length ) * max_length_penalty;
    }

    return Classification( domain, Classification::Note::SCORE, score );
}

Classification DnsClassifier::classify( const DnsPacket& dns )
{
    Classification min_cls;
    for( auto& q: dns.questions ) {
        Classification cls = classify_question( q.qname );
        if( cls < min_cls ) {
            min_cls = cls;
        }
    }
    return min_cls;
}

void DnsClassifier::learn( const DnsPacket& dns )
{
    for( auto& q: dns.questions ) {
        for( auto& c: entropy_classifiers ) {
            c.learn( q.qname );
        }
    }
}

Model DnsClassifier::create_model() const
{
    Model model;
    for( auto& c: entropy_classifiers ) {
        unsigned win_width = c.get_window_width();
        model.entropy_distribution[win_width] =
          c.get_entropy_distribution( DistributionScale::LOG );
    }
    return model;
}

}} // namespace snort::dns_firewall
