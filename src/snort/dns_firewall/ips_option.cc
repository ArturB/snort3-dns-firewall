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

#include "ips_option.h"
#include "dns_packet.h"
#include <protocols/packet.h>

namespace snort { namespace dns_firewall {

dns_firewall::IpsOption::IpsOption( const std::string& config_filename )
    : options( config_filename )
    , snort::IpsOption( module_name )
{
    model.load( options.model_file );

    std::cout << "[DNS Firewall] Current configuration:" << std::endl;
    if( options.mode == Config::Mode::LIVE ) {
        std::cout << "[DNS Firewall]    - mode: live" << std::endl;
    }
    if( options.mode == Config::Mode::SIMPLE ) {
        std::cout << "[DNS Firewall]    - mode: simple" << std::endl;
    }
    std::cout << "[DNS Firewall]    - model-file: " << options.model_file << std::endl;
    std::cout << "[DNS Firewall]    - window widths: ";
    for( auto it = model.entropy_distribution.begin(); it != model.entropy_distribution.end();
         ++it ) {
        std::cout << it->first << " ";
        dns_classifiers.push_back( entropy::DnsClassifier( it->first, it->second.size() ) );
        dns_classifiers.back().set_entropy_distribution(
          it->second, 1000000, DistributionScale::LOG );
    }
    std::cout << std::endl;
    std::cout << "[DNS Firewall]    - min-length: " << options.length.min_length << std::endl;
    std::cout << "[DNS Firewall]    - max-length: " << options.length.max_length << std::endl;
    std::cout << "[DNS Firewall]    - max-length-penalty: " << options.length.max_length_penalty
              << std::endl;
    std::cout << "[DNS Firewall]    - hmm-weight: " << options.hmm.weight << std::endl;
    std::cout << "[DNS Firewall]    - entropy-weight: " << options.entropy.weight << std::endl;
    std::cout << "[DNS Firewall]    - short-reject.block-period: "
              << options.short_reject.block_period << std::endl;
    std::cout << "[DNS Firewall]    - short-reject.threshold: "
              << options.short_reject.threshold << std::endl;
    std::cout << "[DNS Firewall]    - long-reject.block-period: "
              << options.long_reject.block_period << std::endl;
    std::cout << "[DNS Firewall]    - long-reject.threshold: " << options.long_reject.threshold
              << std::endl;
    std::cout << "[DNS Firewall]    - permanent-reject.threshold: "
              << options.permanent_reject.threshold << std::endl;
}

uint32_t dns_firewall::IpsOption::hash() const
{
    return 3984583;
}

bool dns_firewall::IpsOption::operator==( const dns_firewall::IpsOption& operand2 ) const
{
    return true;
}

double dns_firewall::IpsOption::calculate_score( const DnsPacket& dns )
{
    double min_score = 0;
    for( unsigned q = 0; q < dns.question_num; ++q ) {
        double score = 0;
        if( dns.questions[q].qlen < options.length.min_length ) {
            continue;
        }
        for( unsigned c = 0; c < dns_classifiers.size(); ++c ) {
            double s =
              dns_classifiers[c].classify( dns.questions[q].qname );
            // if( s < -10000 ) {
            //     std::cout << "[DNS Firewall] Classifier "
            //               << dns_classifiers[c].get_window_width()
            //               << ", bins = " << dns_classifiers[c].get_distribution_bins()
            //               << " score: " << s << std::endl;
            // }
            score += s;
        }
        score /= dns_classifiers.size();
        if( dns.questions[q].qlen > options.length.max_length ) {
            score -= ( dns.questions[q].qlen - options.length.max_length ) *
                     options.length.max_length_penalty;
        }
        if( score < min_score ) {
            min_score = score;
        }
    }
    return min_score;
}

snort::IpsOption::EvalStatus dns_firewall::IpsOption::eval( Cursor&, Packet* p )
{
    DnsPacket dns = DnsPacket( p->data, p->dsize );
    if( dns.malformed ) {
        std::cout << "[DNS Firewall] Not a DNS query!" << std::endl;
        return NO_MATCH;
    }
    if( dns.questions[0].qtype != 1 ) {
        return NO_MATCH;
    }
    double score = calculate_score( dns );
    if( score < options.short_reject.threshold ) {
        for( unsigned i = 0; i < dns.question_num; ++i ) {
            std::cout << "[DNS Firewall] " << dns.questions[i].qname << " (" << i + 1 << "/"
                      << dns.question_num << "), score = " << score << ", REJECT" << std::endl;
        }
        return MATCH;
    }
    return NO_MATCH;
}

}} // namespace snort::dns_firewall
