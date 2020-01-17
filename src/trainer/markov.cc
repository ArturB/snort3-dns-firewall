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

#include <algorithm>
#include <armadillo>
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

extern char* optarg;

using namespace std;
using namespace arma;

// Runtime options of the program
class ProgramOptions
{
  public:
    unsigned markov_states_;
    string data_filename_;
    string output_filename_;

  public:
    ProgramOptions( int argc, char* const argv[] )
        : markov_states_( 10 )
        , data_filename_()
        , output_filename_( "snort4gini.out" )
    {
        int opt;
        while( ( opt = getopt( argc, argv, "s:f:o:" ) ) != -1 ) {
            switch( opt ) {
            case 's':
                markov_states_ = static_cast<unsigned>( stoi( optarg ) );
                break;
            case 'f':
                data_filename_ = string( optarg );
                break;
            case 'o':
                output_filename_ = string( optarg );
                break;
            }
        }
        if( data_filename_.empty() ) {
            print_help();
            exit( 1 );
        }
    }

    void print_help()
    {
        string help =
          "snort4gini usage:\n"
          "   -f: File name of the dataset to process (mandatory)\n"
          "   -o: Output file name (default: snort4gini.out)\n"
          "   -s: Number of Markov chain hidden states (default: 10)\n";
        cout << help << endl;
    }
};

//------------//
// ENTRYPOINT //
//------------//
int main( int argc, char* const argv[] )
{
    // Load and print program options
    cout << "snort4markov 0.1.1 by Artur M. Brodzki" << endl;
    ProgramOptions options = ProgramOptions( argc, argv );

    cout << "Dataset file name = " << options.data_filename_ << endl;
    cout << "Hidden Markov states = " << options.markov_states_ << endl;
    cout << "Output file name = " << options.output_filename_ << endl;

    cout << "Processing data..." << endl;

    mat A = randu<mat>( 4, 5 );
    mat B = randu<mat>( 4, 5 );

    cout << A * B.t() << endl;

    return 0;
}
