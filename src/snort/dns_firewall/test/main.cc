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

#include "config.h"
#include "dns_classifier.h"
#include "dns_packet.h"
#include "model.h"

extern char* optarg;

using namespace snort::dns_firewall;

// ----------------
// ENTRYPOINT
// ----------------
int main( int argc, char* const argv[] )
{
    std::cout << "testdfw3 0.1.1 by Artur M. Brodzki" << std::endl << std::endl;
    std::string help =
      "Usage:\n"
      "   -c: YAML config file name (mandatory)\n\n"
      "       If -f, -n, -m, -o option is specified, configuration\n"
      "       from YAML file is overwritten.\n\n"
      "   -f: File name of the test dataset to process\n"
      "   -n: max number of lines to process\n"
      "   -m: Model file name\n"
      "   -o: Output file name\n"
      "   -h: Print this help\n";

    // Parse command line options
    int opt;
    std::string graphs_path;
    std::string yaml_filename_getopt;
    std::string dataset_filename_getopt;
    std::string output_filename_getopt;
    std::string model_filename_getopt;
    int max_lines_getopt = -1;

    while( ( opt = getopt( argc, argv, "c:f:n:m:o:h" ) ) != -1 ) {
        switch( opt ) {
        case 'c':
            yaml_filename_getopt = std::string( optarg );
            break;
        case 'f':
            dataset_filename_getopt = std::string( optarg );
            break;
        case 'n':
            max_lines_getopt = std::stoi( optarg );
            break;
        case 'm':
            model_filename_getopt = std::string( optarg );
            break;
        case 'o':
            output_filename_getopt = std::string( optarg );
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
    Config options = Config( yaml_filename_getopt );
    if( model_filename_getopt != "" ) {
        options.model.filename = model_filename_getopt;
    }
    // Turn off timeframe classifier
    options.timeframe.enabled = false;

    // Load model
    Model model;
    model.load_from_file( options.model.filename );
    // Print basic model characteristics
    std::cout << model << std::endl << std::endl;

    // Create DNS classifier
    snort::dns_firewall::DnsClassifier cls( options );

    // Process data line by line
    std::ifstream dataset_file( dataset_filename_getopt );
    std::ofstream output_file( output_filename_getopt );
    std::string line;
    unsigned processed_lines = 0;
    unsigned skipped_lines   = 0;
    std::cout.imbue( std::locale( "" ) );

    output_file << "DOMAIN;HMM;ENTROPY;TOTAL" << std::endl;

    while( getline( dataset_file, line ) ) {
        if( line.empty() ) {
            continue;
        }
        if( max_lines_getopt > 0 && processed_lines >= (unsigned) max_lines_getopt ) {
            break;
        }
        if( processed_lines % 1 == 0 && line.size() >= options.hmm.min_length ) {
            try {
                auto result = cls.classify( DnsPacket( line ) );
                output_file << result.domain << ";" << result.score1 << ";" << result.score2
                            << ";" << result.score << std::endl;
            } catch( ... ) {
                std::cout << "CATCH: " << line << std::endl;
                ++skipped_lines;
                continue;
            }
        }
        ++processed_lines;
        // Print progress in real-time
        if( processed_lines % 1024 == 0 ) {
            std::cout << "\rProcessed lines: " << processed_lines << "    " << std::flush;
        }
    }

    std::cout << "\rTest results saved to " << output_filename_getopt << "!" << std::endl;
    std::cout << "Processed lines: " << processed_lines << std::endl;
    std::cout << "Skipped lines: " << skipped_lines << std::endl;

    return 0;
}
