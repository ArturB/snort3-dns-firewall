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

#ifndef SNORT_DNS_FIREWALL_TRAINER_ENTROPY_DNS_CLASSIFIER_H
#define SNORT_DNS_FIREWALL_TRAINER_ENTROPY_DNS_CLASSIFIER_H

#include "distribution_scale.h"
#include <queue>
#include <unordered_map>

namespace snort { namespace dns_firewall { namespace entropy {

class DnsClassifier
{
  private:
    // FIFO DNS queries buffer
    std::queue<std::string> dns_fifo_; // FIFO queue of processed domains
    unsigned dns_fifo_size_;           // Memoized size of above FIFO queue
    double current_metric_;            // Memoized concentration metric of current FIFO
    unsigned window_width_;            // Max FIFO size
    std::unordered_map<std::string, unsigned> freq_; // Mapping from FLDs to its frequencies

    // Entropy probability distribution
    std::vector<unsigned>
      entropy_distribution_; // Probability distribution of entropy,
                             // stored as number of observations for distribution bins
    unsigned dist_bins_;     // Number of bins in entropy distribution

    // Internal state
    bool state_shift_; // If true, maximal size of FIFO queue is reached and domains are shifted
                       // using pop

  private:
    // Get x-level suffix of DNS domain from string
    // e.g. for GetDnsFld(s2.smtp.google.com, 2) function returns google.com
    // dont work for empty string
    static std::string get_dns_xld( const std::string&, unsigned ) noexcept;

    // Calculates given metric for one FLD
    double domain_metric( unsigned ) const noexcept;

    // Calculate given metric for dns_fifo
    double fifo_metric() const noexcept;

    // Insert new domain to window
    // Updates current_metric value
    void insert( const std::string& ) noexcept;

    // Pop domain from window
    // Updates current_metric value
    void pop() noexcept;

    // Shift window to new domain
    void forward_shift( const std::string& ) noexcept;

  public:
    // Default constructor
    DnsClassifier( unsigned window_width, unsigned dist_bins ) noexcept;

    // Get entropy distribution
    std::vector<double> get_entropy_distribution( snort::dns_firewall::DistributionScale ) const
      noexcept;
    // Set entropy distribution
    void set_entropy_distribution( const std::vector<double>&,
                                   unsigned,
                                   snort::dns_firewall::DistributionScale );
    // Get number of distribution bins
    unsigned get_distribution_bins() const noexcept;
    // Get current window width
    unsigned get_window_width() const noexcept;

    // Learn classifier with one DNS domain
    void learn( const std::string& ) noexcept;
    // Classify DNS domain
    double classify( const std::string& ) noexcept;
};

}}} // namespace snort::dns_firewall::entropy

#endif // SNORT_DNS_FIREWALL_TRAINER_ENTROPY_DNS_CLASSIFIER_H
