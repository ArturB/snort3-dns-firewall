/// **********************************************************************
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

#include "getopt_parser.h"
#include <algorithm>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <getopt.h>
#include <iostream>
#include <queue>
#include <set>
#include <sstream>
#include <string>
#include <unistd.h>
#include <unordered_map>
#include <vector>

namespace snort
{
namespace dns_firewall
{
namespace trainer
{

GetoptParser::GetoptParser( int argc, char* const argv[] )
    : bins_( 1000 )
    , window_size_( 1000 )
    , max_lines_( 1e9 )
    , data_filename_()
    , output_filename_( "snort4gini.out" )
    , log_distribution_( false )
{
    int opt;
    while( ( opt = getopt( argc, argv, "b:f:ln:o:w:" ) ) != -1 ) {
        switch( opt ) {
        case 'b':
            bins_ = static_cast<unsigned>( std::stoi( optarg ) );
            break;
        case 'f':
            data_filename_ = std::string( optarg );
            break;
        case 'l':
            log_distribution_ = true;
            break;
        case 'n':
            max_lines_ = static_cast<unsigned>( std::stoi( optarg ) );
            break;
        case 'o':
            output_filename_ = std::string( optarg );
            break;
        case 'w':
            window_size_ = static_cast<unsigned>( std::stoi( optarg ) );
            break;
        }
    }
    if( data_filename_.empty() ) {
        print_help();
        exit( 1 );
    }
}

void GetoptParser::print_help()
{
    std::string help =
      "\n"
      "snort4gini usage:\n"
      "   -b: Number of bins when estimating distribution (default: 1000)\n"
      "   -f: File name of the dataset to process (mandatory)\n"
      "   -l: if flag set, the result distribution will be in log scale (default: no)\n"
      "   -n: max number of lines to process (default: 1e9)\n"
      "   -o: Output file name (default: snort4gini.out)\n"
      "   -w: size of shifting window (default: 1000)\n";
    std::cout << help << std::endl;
}

} // namespace trainer
} // namespace dns_firewall
} // namespace snort
