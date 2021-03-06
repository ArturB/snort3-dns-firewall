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

#include "classification.h"

namespace snort { namespace dns_firewall {

Classification::Classification()
    : note( Note::SCORE )
    , score( 0 )
    , score1( 0 )
    , score2( 0 )
{
}

Classification::Classification( const std::string& domain,
                                Classification::Note note,
                                double score,
                                double score1,
                                double score2 )
    : domain( domain )
    , note( note )
    , score( score )
    , score1( score1 )
    , score2( score2 )
{
}

bool Classification::operator==( const Classification& operand2 ) const
{
    return note == operand2.note && score == operand2.score;
}

bool Classification::operator<( const Classification& operand2 ) const
{
    return note < operand2.note || score < operand2.score;
}

bool Classification::operator>( const Classification& operand2 ) const
{
    return note > operand2.note || score > operand2.score;
}

std::ostream& operator<<( std::ostream& os, const Classification& cls )
{
    if( cls.note == Classification::Note::BLACKLIST ) {
        os << "[DNS Firewall] " << cls.domain << " BLACKLIST";
    }
    if( cls.note == Classification::Note::WHITELIST ) {
        os << "[DNS Firewall] " << cls.domain << " WHITELIST";
    }
    if( cls.note == Classification::Note::MAX_LENGTH ) {
        os << "[DNS Firewall] " << cls.domain << " MAX_LENGTH " << cls.score1 << "/"
           << cls.score2;
    }
    if( cls.note == Classification::Note::INVALID_TIMEFRAME ) {
        os << "[DNS Firewall] " << cls.domain << " INVALID_TIMEFRAME " << cls.score1 << "/"
           << cls.score2;
    }
    if( cls.note == Classification::Note::MIN_LENGTH ) {
        os << "[DNS Firewall] " << cls.domain << " TOO SHORT";
    }
    if( cls.note == Classification::Note::SCORE ) {
        os << "[DNS Firewall] " << cls.domain << " SCORE hmm = " << cls.score1
           << ", entropy = " << cls.score2 << ", total = " << cls.score;
    }
    return os;
}

}} // namespace snort::dns_firewall
