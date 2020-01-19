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

#ifndef SNORT_DNS_FIREWALL_TRAINER_GETOPT_PARSER_H
#define SNORT_DNS_FIREWALL_TRAINER_GETOPT_PARSER_H

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

// Runtime options of the program
class GetoptParser
{
  public:
    unsigned bins_;
    unsigned window_size_;
    unsigned max_lines_;
    std::string data_filename_;
    std::string output_filename_;
    bool log_distribution_;

  public:
    GetoptParser( int argc, char* const argv[] );
    static void print_help();
};

} // namespace trainer
} // namespace dns_firewall
} // namespace snort

#endif // SNORT_DNS_FIREWALL_TRAINER_GETOPT_PARSER_H
