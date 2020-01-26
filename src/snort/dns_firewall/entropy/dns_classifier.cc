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

#include "dns_classifier.h"
#include "distribution_scale.h"

namespace snort
{
namespace dns_firewall
{
namespace entropy
{

DnsClassifier::DnsClassifier( unsigned window_width, unsigned bins ) noexcept
    : window_width_( window_width )
    , entropy_distribution_( bins, 0 )
    , dist_bins_( bins )
    , state_shift_( false )
    , current_metric_( 0 )
    , dns_fifo_size_( 0 )
{
}

// Get x-level suffix of DNS domain from string
// e.g. for GetDnsFld(s2.smtp.google.com, 2) function returns google.com
// dont work for empty string
std::string DnsClassifier::get_dns_xld( const std::string& domain, unsigned level ) noexcept
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
    return domain;
}

// Calculates given metric for one domain
double DnsClassifier::domain_metric( unsigned domain_val ) const noexcept
{
    if( domain_val == 0 ) {
        return 0.0;
    } else {
        double domain_freq = double( domain_val ) / double( dns_fifo_size_ );

        return -1 * domain_freq * log( domain_freq );
    }
}

// Calculate given metric for dns_fifo
double DnsClassifier::fifo_metric() const noexcept
{
    double metric_value = 0;
    for( auto it = freq_.begin(); it != freq_.end(); ++it ) {
        metric_value += domain_metric( it->second );
    }
    return metric_value / log( dns_fifo_.size() );
}

// Insert new domain to window
// Updates current_metric value
void DnsClassifier::insert( const std::string& domain ) noexcept
{
    dns_fifo_.push( domain );
    ++freq_[domain];
    ++dns_fifo_size_;
    current_metric_ = fifo_metric();
}

// Pop domain from window
// Updates current_metric value
void DnsClassifier::pop() noexcept
{
    std::string domain = dns_fifo_.front();
    // Pop domain
    dns_fifo_.pop();
    --dns_fifo_size_;
    if( --freq_[domain] == 0 )
        freq_.erase( domain );
    current_metric_ = fifo_metric();
}

// Shift window to new domain
void DnsClassifier::forward_shift( const std::string& domain ) noexcept // 53 cycles
{
    std::string popped = dns_fifo_.front(); // 20 cycles

    if( domain == popped ) {      // 4 cycles
        dns_fifo_.push( domain ); // 50 cycles
        dns_fifo_.pop();          // 50 cycles
    } else {
        unsigned old_inserted_domain_freq = freq_[domain]++; // 140 cycles
        unsigned old_popped_domain_freq   = freq_[popped]--; // 140 cycles

        double old_inserted_domain_metric =
          domain_metric( old_inserted_domain_freq );                               // 40 cycles
        double old_popped_domain_metric = domain_metric( old_popped_domain_freq ); // 40 cycles

        double new_inserted_domain_metric =
          domain_metric( old_inserted_domain_freq + 1 ); // 40 cycles
        double new_popped_domain_metric =
          domain_metric( old_popped_domain_freq - 1 ); // 40 cycles

        double delta_inserted =
          new_inserted_domain_metric - old_inserted_domain_metric;                 // 4 cycles
        double delta_popped = new_popped_domain_metric - old_popped_domain_metric; // 4 cycles

        current_metric_ +=
          ( delta_inserted + delta_popped ) / log( dns_fifo_size_ ); // 3 cycles

        dns_fifo_.push( domain ); // 50 cycles
        dns_fifo_.pop();          // 50 cycles

        if( old_popped_domain_freq == 1 )
            freq_.erase( popped );
    }

    if( current_metric_ < 1e-10 ) {
        current_metric_ = fifo_metric();
    }
}

std::vector<double>
DnsClassifier::get_entropy_distribution( snort::dns_firewall::DistributionScale scale ) const
  noexcept
{
    std::vector<double> distribution_values = std::vector<double>( dist_bins_, 0 );

    unsigned observations_count = 0;
    for( unsigned i = 0; i < dist_bins_; ++i ) {
        observations_count += entropy_distribution_[i];
    }

    if( scale == snort::dns_firewall::DistributionScale::LOG ) {
        for( unsigned i = 0; i < dist_bins_; ++i ) {
            distribution_values[i] = entropy_distribution_[i] + 1;
        }
        for( unsigned i = 0; i < dist_bins_; ++i ) {
            distribution_values[i] =
              log10( double( distribution_values[i] ) / double( observations_count ) );
        }
    } else {
        for( unsigned i = 0; i < dist_bins_; ++i ) {
            distribution_values[i] =
              double( entropy_distribution_[i] ) / double( observations_count );
        }
    }

    return distribution_values;
}

void DnsClassifier::set_entropy_distribution(
  const std::vector<double>& dist, unsigned weight,
  snort::dns_firewall::DistributionScale scale )
{
    dist_bins_ = dist.size();

    std::vector<unsigned> distribution_values = std::vector<unsigned>( dist_bins_, 0 );
    for( unsigned i = 0; i < dist_bins_; ++i ) {
        if( scale == snort::dns_firewall::DistributionScale::LOG ) {
            distribution_values[i] = weight * pow( 10, dist[i] );
        } else {
            distribution_values[i] = weight * dist[i];
        }
    }
    entropy_distribution_ = distribution_values;
}

unsigned DnsClassifier::get_distribution_bins() const noexcept
{
    return dist_bins_;
}

unsigned DnsClassifier::get_window_width() const noexcept
{
    return window_width_;
}

void DnsClassifier::learn( const std::string& domain ) noexcept
{
    if( state_shift_ ) {
        forward_shift( get_dns_xld( domain, 2 ) );
        unsigned distribution_bin = floor( current_metric_ * dist_bins_ );
        ++entropy_distribution_[distribution_bin];
    } else {
        insert( get_dns_xld( domain, 2 ) );
        if( dns_fifo_.size() >= window_width_ ) {
            state_shift_ = true;
        }
    }
}

double DnsClassifier::classify( const std::string& domain, DistributionScale scale ) noexcept
{
    if( not state_shift_ ) {
        insert( get_dns_xld( domain, 2 ) );
        if( dns_fifo_.size() >= window_width_ ) {
            state_shift_ = true;
        }
        if( scale == snort::dns_firewall::DistributionScale::LOG ) {
            return 0;
        } else {
            return 1;
        }
    }

    forward_shift( get_dns_xld( domain, 2 ) );
    unsigned distribution_bin   = floor( current_metric_ * dist_bins_ );
    unsigned observations_count = 0;
    for( unsigned i = 0; i < dist_bins_; ++i ) {
        observations_count += entropy_distribution_[i];
    }
    double prob =
      double( entropy_distribution_[distribution_bin] ) / double( observations_count );
    if( scale == snort::dns_firewall::DistributionScale::LOG ) {
        return log10( prob );
    } else {
        return prob;
    }
}

} // namespace entropy
} // namespace dns_firewall
} // namespace snort
