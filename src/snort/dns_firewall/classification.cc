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
{
}

Classification::Classification( const std::string& domain,
                                Classification::Note note,
                                double score )
    : domain( domain )
    , note( note )
    , score( score )
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

}} // namespace snort::dns_firewall
