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

#include "entropy/dns_classifier.h"
#include "hmm/dns_classifier.h"
#include "model.h"
#include "trainer/config.h"

extern char* optarg;

using namespace snort::dns_firewall;

// ----------------
// ENTRYPOINT
// ----------------
int main( int argc, char* const argv[] )
{
    std::cout << "snort3trainer 0.1.1 by Artur M. Brodzki" << std::endl << std::endl;
    std::string help =
      "Usage:\n"
      "   -c: YAML config file name (mandatory)\n\n"
      "       If -f, -n, -o option is specified, configuration\n"
      "       from YAML file is overwritten.\n\n"
      "   -f: File name of the dataset to process\n"
      "   -n: max number of lines to process\n"
      "   -o: Model file name\n"
      "   -h: Print this help\n";

    // Parse command line options
    int opt;
    bool save_graphs = false;
    std::string graphs_path;
    std::string yaml_filename_getopt;
    std::string dataset_filename_getopt;
    std::string model_filename_getopt;
    int max_lines_getopt = -1;

    while( ( opt = getopt( argc, argv, "g:c:f:n:o:h" ) ) != -1 ) {
        switch( opt ) {
        case 'g':
            save_graphs = true;
            graphs_path = std::string( optarg );
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
    // Load config file
    std::cout << "Config file: " << yaml_filename_getopt << std::endl;
    trainer::Config options = trainer::Config( yaml_filename_getopt );
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
    std::cout << options << std::endl << std::endl;

    // Create line_processor objects
    std::vector<entropy::DnsClassifier> fifos;
    for( auto& w: options.entropy.window_widths ) {
        fifos.push_back( entropy::DnsClassifier( w, options.entropy.bins ) );
    }
    // Process data line by line
    std::ifstream dataset_file( options.dataset );
    std::string line;
    unsigned processed_lines = 0;

    std::cout.imbue( std::locale( "" ) );
    std::vector<std::string> line_buf;
    while( getline( dataset_file, line ) ) {
        if( line.empty() ) {
            continue;
        }
        if( options.max_lines > 0 && processed_lines >= (unsigned) options.max_lines ) {
            break;
        }
        line_buf.push_back( line );
        // If line buffer is big enough, learn each classifier in separate thread
        if( line_buf.size() == 16384 ) {
#pragma omp parallel for
            for( unsigned i = 0; i < fifos.size(); ++i ) {
                for( auto& l: line_buf ) {
                    fifos[i].learn( l );
                }
            }
            line_buf.clear();
        }
        ++processed_lines;
        if( processed_lines % 1024 == 0 ) {
            std::cout << "\rProcessed lines: " << processed_lines << "    " << std::flush;
        }
    }

    // Create model file
    snort::dns_firewall::Model model;
    for( auto& f: fifos ) {
        unsigned win_width = f.get_window_width();
        model.entropy_distribution[win_width] =
          f.get_entropy_distribution( options.entropy.scale );
    }

    // Save result distribution to file
    model.save( options.model_file );
    std::cout << "\rDistribution saved to " << options.model_file << "!" << std::endl;
    std::cout << "Processed lines: " << processed_lines << std::endl;

    if( save_graphs ) {
        model.save_graphs( graphs_path );
    }

    return 0;
}
