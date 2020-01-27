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

namespace snort { namespace dns_firewall {

dns_firewall::IpsOption::IpsOption( const std::string& config_filename )
    : options( config_filename )
    , classifier( options )
    , snort::IpsOption( "dns_firewall" )
{
}

uint32_t dns_firewall::IpsOption::hash() const
{
    return 3984583;
}

bool dns_firewall::IpsOption::operator==( const dns_firewall::IpsOption& operand2 ) const
{
    return true;
}

snort::IpsOption::EvalStatus dns_firewall::IpsOption::eval( Cursor&, Packet* p )
{
    DnsPacket dns( p->data, p->dsize );
    if( dns.malformed ) {
        std::cout << "[DNS Firewall] Packet received on UDP port 53, but not a DNS query!"
                  << std::endl;
        return NO_MATCH;
    }

    Classification cls = classifier.classify( dns );
    // std::cout << cls.domain << ", note = " << cls.note << ", score = " << cls.score
    //           << std::endl;
    if( cls.note == Classification::Note::BLACKLIST ) {
        std::cout << "[DNS Firewall] " << cls.domain << " REJECT (blacklist)" << std::endl;
        return MATCH;
    }
    if( cls.note == Classification::Note::WHITELIST ) {
        std::cout << "[DNS Firewall] " << cls.domain << " ACCEPT (whitelist)" << std::endl;
        return NO_MATCH;
    }
    if( cls.note == Classification::Note::MIN_LENGTH ) {
        std::cout << "[DNS Firewall] " << cls.domain << " ACCEPT (too short)" << std::endl;
        return NO_MATCH;
    }
    if( cls.note == Classification::Note::SCORE ) {
        if( cls.score < options.short_reject.threshold ) {
            std::cout << "[DNS Firewall] " << cls.domain << " REJECT (score = " << cls.score
                      << ")" << std::endl;
            return MATCH;
        }
    }
    return NO_MATCH; // should never execute
}

}} // namespace snort::dns_firewall
