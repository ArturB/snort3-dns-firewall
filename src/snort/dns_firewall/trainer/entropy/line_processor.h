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

#ifndef SNORT_DNS_FIREWALL_TRAINER_ENTROPY_LINE_PROCESSOR_H
#define SNORT_DNS_FIREWALL_TRAINER_ENTROPY_LINE_PROCESSOR_H

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
namespace entropy
{

class LineProcessor
{
 private:
    double current_metric_;                          // Memoized concentration metric
    unsigned dist_bins_;                             // Number of bins in metrics distribution
    std::queue<std::string> dns_fifo_;               // FIFO queue of processed domains
    unsigned dns_fifo_size_;                         // Memoized size of above FIFO queue
    unsigned window_width_;                          // Target window width
    unsigned processed_lines_;                       // Number of lines processed so far
    std::unordered_map<std::string, unsigned> freq_; // Mapping from domain to its frequencies

 public:
    std::vector<unsigned>
      distribution_; // Probability distribution of metrics,
                     // stored as number of observations for distribution bins

 private:
    // Calculates given metric for one domain
    double domain_metric( unsigned ) const;

    // Calculate given metric for dns_fifo
    double fifo_metric() const;

    // Insert new domain to window
    // Updates current_metric value
    void insert( const std::string& );

    // Pop domain from window
    // Updates current_metric value
    void pop();

    // Shift window to new domain
    void forward_shift( const std::string& );

 public:
    // Default constructor
    explicit LineProcessor( unsigned, unsigned );

    // Process DNS line
    void process_line( const std::string& );

    // Get distribution vector
    std::vector<double> get_distribution( bool ) const;

    // Get current window width
    unsigned get_window_width() const;

}; // namespace trainerclassLineProcessor

} // namespace entropy
} // namespace trainer
} // namespace dns_firewall
} // namespace snort

#endif // SNORT_DNS_FIREWALL_TRAINER_ENTROPY_LINE_PROCESSOR_H
