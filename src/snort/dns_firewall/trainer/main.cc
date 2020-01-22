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

#include "model.h"
#include "trainer/config.h"
#include "trainer/entropy/line_processor.h"
#include "trainer/hmm/line_processor.h"
#include <algorithm>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <getopt.h>
#include <iostream>
#include <locale>
#include <queue>
#include <set>
#include <sstream>
#include <string>
#include <unistd.h>
#include <unordered_map>
#include <vector>
#include <yaml-cpp/yaml.h>

extern char* optarg;

using namespace snort::dns_firewall::trainer;

// Get x-level suffix of DNS domain from string
// e.g. for GetDnsFld(s2.smtp.google.com, 2) function returns google.com
// dont work for empty string
static std::string get_dns_xld( const std::string& domain, unsigned level )
{
    char delimiter             = '.';
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
    std::cout << "snort3trainer 0.1.1 by Artur M. Brodzki" << std::endl;
    std::string help =
      "\n"
      "Usage:\n"
      "   -c: YAML config file name (mandatory)\n"
      "       If -f, -n, -o option is specified, configuration\n"
      "       from YAML file is overwritten.\n\n"
      "   -f: File name of the dataset to process\n"
      "   -n: max number of lines to process\n"
      "   -o: Model file name\n"
      "   -h: Print this help\n";

    // Load config.yaml file
    int opt;
    bool save_graphs = false;
    std::string yaml_filename_getopt;
    std::string dataset_filename_getopt;
    std::string model_filename_getopt;
    int max_lines_getopt = -1;

    while( ( opt = getopt( argc, argv, "gc:f:n:o:h" ) ) != -1 ) {
        switch( opt ) {
        case 'g':
            save_graphs = true;
            break;
        case 'c':
            yaml_filename_getopt = std::string( optarg );
            break;
        case 'f':
            dataset_filename_getopt = std::string( optarg );
            break;
        case 'n':
            max_lines_getopt = std::stoi( optarg );
            break;
        case 'o':
            model_filename_getopt = std::string( optarg );
            break;
        case 'h':
            std::cout << help << std::endl;
            exit( 0 );
            break;
        }
    }
    if( yaml_filename_getopt == "" ) {
        std::cout << help << std::endl;
        exit( 1 );
    }
    std::cout << "Config file: " << yaml_filename_getopt << std::endl;
    Config options = Config( yaml_filename_getopt );
    if( dataset_filename_getopt != "" ) {
        options.dataset = dataset_filename_getopt;
    }
    if( model_filename_getopt != "" ) {
        options.model_file = model_filename_getopt;
    }
    if( max_lines_getopt != -1 ) {
        options.max_lines = max_lines_getopt;
    }

    // Load and print trainer options
    std::cout << std::endl << "Dataset file name = " << options.dataset << std::endl;
    std::cout << "Window sizes = ";
    for( unsigned i = 0; i < options.entropy.window_widths.size(); ++i ) {
        std::cout << options.entropy.window_widths[i] << " ";
    }
    std::cout << std::endl;
    std::cout << "Distribution Bins = " << options.entropy.bins << std::endl;
    std::cout << "Output file name = " << options.model_file << std::endl;
    if( options.entropy.log_scale ) {
        std::cout << std::endl << "Generating log-scale distribution..." << std::endl;
    }

    // Create line_processor objects
    std::vector<entropy::LineProcessor> fifos;
    for( unsigned i = 0; i < options.entropy.window_widths.size(); ++i ) {
        fifos.push_back(
          entropy::LineProcessor( options.entropy.window_widths[i], options.entropy.bins ) );
    }

    // Process data line by line
    std::ifstream dataset_file( options.dataset );
    std::string line;
    unsigned processed_lines = 0;

    std::cout.imbue( std::locale( "" ) );
    while( getline( dataset_file, line ) && processed_lines < options.max_lines ) {
        if( line.empty() ) {
            continue;
        } else {
            std::string xld = get_dns_xld( line, 2 );
            for( unsigned i = 0; i < fifos.size(); ++i ) {
                fifos[i].process_line( xld );
            }
        }
        ++processed_lines;
        if( processed_lines % 1024 == 0 ) {
            std::cout << "\rProcessed lines: " << processed_lines << "    " << std::flush;
        }
    }

    // Create model file
    snort::dns_firewall::Model model;
    for( unsigned i = 0; i < fifos.size(); ++i ) {
        unsigned win_width = fifos[i].get_window_width();
        model.entropy_distribution[win_width] =
          fifos[i].get_distribution( options.entropy.log_scale );
    }

    // Save result distribution to file
    model.save( options.model_file );
    std::cout << "\rDistribution saved to " << options.model_file << "!" << std::endl;
    std::cout << "Processed lines: " << processed_lines << std::endl;

    if( save_graphs ) {
        model.save_graphs("bin/rb-");
    }

    return 0;
}
