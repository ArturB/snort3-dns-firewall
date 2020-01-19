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

#include "trainer/entropy/line_processor.h"
#include "trainer/getopt_parser.h"
#include "trainer/hmm/line_processor.h"
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

using namespace snort::dns_firewall;

// Get x-level suffix of DNS domain from string
// e.g. for GetDnsFld(s2.smtp.google.com, 2) function returns google.com
// dont work for empty string
static std::string GetDnsFld( const std::string& domain, unsigned level )
{
    char delimiter = '.';
    unsigned delimiters_passed = 0;
    for( unsigned long i = domain.length() - 1; i > 0; --i ) {
        if( domain[i] == delimiter ) {
            ++delimiters_passed;
            if( delimiters_passed == level )
                return domain.substr( i + 1, domain.size() );
        }
    }
    return std::string( domain );
}

// ----------------
// ENTRYPOINT
// ----------------
int main( int argc, char* const argv[] )
{
    // Load and print program options
    std::cout << "snort4gini 0.1.1 by Artur M. Brodzki" << std::endl;
    trainer::GetoptParser options = trainer::GetoptParser( argc, argv );

    std::cout << "Dataset file name = " << options.data_filename_ << std::endl;
    std::cout << "Window size = " << options.window_size_ << std::endl;
    std::cout << "Distribution Bins = " << options.bins_ << std::endl;
    std::cout << "Output file name = " << options.output_filename_ << std::endl;
    if( options.log_distribution_ )
        std::cout << "Generating log-scale distribution..." << std::endl;

    std::cout << "Processing data..." << std::endl;

    // Process data line by line
    std::ifstream dataset_file( options.data_filename_ );
    std::string line;
    unsigned processed_lines = 0;
    trainer::entropy::LineProcessor window( options.bins_ );

    while( getline( dataset_file, line ) && processed_lines < options.max_lines_ ) {
        if( line.empty() )
            continue;
        else if( processed_lines <= options.window_size_ ) {
            window.insert( GetDnsFld( line, 2 ) );
        } else {
            window.forward_shift( GetDnsFld( line, 2 ) );
        }
        ++processed_lines;
    }

    // Save result distribution to file
    window.save_distribution( options.output_filename_, options.log_distribution_ );
    std::cout << "Distribution saved to " << options.output_filename_ << "!" << std::endl;
    std::cout << "Processed lines: " << processed_lines << std::endl;
    return 0;
}
