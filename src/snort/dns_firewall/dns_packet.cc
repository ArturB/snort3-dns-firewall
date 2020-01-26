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

#include "dns_packet.h"

namespace snort { namespace dns_firewall {

DnsPacket::DnsPacket( Packet* p )
    : id( ( p->data[0] << 8 ) + p->data[1] )
    , flags( ( p->data[2] << 8 ) + p->data[3] )
    , question_num( ( p->data[4] << 8 ) + p->data[5] )
    , answer_num( ( p->data[6] << 8 ) + p->data[7] )
    , authority_num( ( p->data[8] << 8 ) + p->data[9] )
    , additional_num( ( p->data[10] << 8 ) + p->data[11] )
    , malformed( false )
    , questions() {
    int cursor_pos = 12;
    for( int i = 0; i < this->question_num; ++i ) {
        DnsPacket::Question q;
        unsigned char buf[255];
        buf[0] = 0;

        while( cursor_pos < p->dsize && p->data[cursor_pos] &&
               cursor_pos + p->data[cursor_pos] < p->dsize ) {

            strncat(
              (char*) &buf[q.qlen], (char*) &( p->data[cursor_pos + 1] ), p->data[cursor_pos] );
            q.qlen += p->data[cursor_pos] + 1;
            strcat( (char*) &buf[q.qlen - 1], "." );
            cursor_pos += 1 + p->data[cursor_pos];
        }

        if( p->data[cursor_pos] != 0 || cursor_pos + 5 > p->dsize ) {
            malformed = true;
            break;
        }

        --q.qlen;
        q.qtype = ( p->data[cursor_pos + 1] << 8 ) + p->data[cursor_pos + 2];

        for( unsigned j = 0; j < q.qlen; ++j ) {
            q.qname.push_back( std::tolower( buf[j] ) );
        }
        questions.push_back( q );
    }
}

}} // namespace snort::dns_firewall
