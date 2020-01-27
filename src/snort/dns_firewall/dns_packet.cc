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

DnsPacket::DnsPacket( const uint8_t* data, unsigned dsize )
    : id( ( data[0] << 8 ) + data[1] )
    , flags( ( data[2] << 8 ) + data[3] )
    , question_num( ( data[4] << 8 ) + data[5] )
    , answer_num( ( data[6] << 8 ) + data[7] )
    , authority_num( ( data[8] << 8 ) + data[9] )
    , additional_num( ( data[10] << 8 ) + data[11] )
    , malformed( false )
    , questions()
{
    unsigned cursor_pos = 12;
    for( unsigned i = 0; i < this->question_num; ++i ) {
        DnsPacket::Question q;
        while( cursor_pos < dsize && data[cursor_pos] &&
               cursor_pos + data[cursor_pos] < dsize ) {

            for( unsigned j = 0; j < data[cursor_pos]; ++j ) {
                q.qname.push_back( data[cursor_pos + 1 + j] );
            }
            q.qname.push_back( '.' );
            q.qlen += data[cursor_pos] + 1;
            cursor_pos += 1 + data[cursor_pos];
        }
        if( data[cursor_pos] != 0 || cursor_pos + 5 > dsize ) {
            malformed = true;
            break;
        }
        q.qname.pop_back();
        --q.qlen;
        q.qtype = ( data[cursor_pos + 1] << 8 ) + data[cursor_pos + 2];
        questions.push_back( q );
    }
}

}} // namespace snort::dns_firewall
