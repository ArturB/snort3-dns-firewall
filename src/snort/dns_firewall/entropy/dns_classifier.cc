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
#include "iostream"
#include <algorithm>
#include <cmath>
#include <numeric>

namespace snort { namespace dns_firewall { namespace entropy {

DnsClassifier::DnsClassifier( unsigned window_width, unsigned bins ) noexcept
    : dns_fifo_size_( 0 )
    , current_metric_( 0 )
    , window_width_( window_width )
    , entropy_distribution_( bins, 0 )
    , dist_bins_( bins )
    , state_shift_( false )
{
}

// Get x-level suffix of DNS domain from string
// e.g. for GetDnsFld(s2.smtp.google.com, 2) function returns google.com
// dont work for empty string
std::string DnsClassifier::get_dns_xld( const std::string& domain, unsigned level ) noexcept
{
    char delimiter             = '.';
    unsigned delimiters_passed = 0;
    for( unsigned i = domain.length() - 1; i > 0; --i ) {
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
    double metric_value =
      std::accumulate( freq_.begin(), freq_.end(), 0, [this]( auto acc, auto f2 ) {
          return acc + domain_metric( f2.second );
      } );
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

    unsigned observations_count =
      std::accumulate( entropy_distribution_.begin(), entropy_distribution_.end(), 0 );

    if( scale == snort::dns_firewall::DistributionScale::LOG ) {
        std::transform( entropy_distribution_.begin(),
                        entropy_distribution_.end(),
                        distribution_values.begin(),
                        [&]( const auto& v ) {
                            return log10( double( v + 1 ) / double( observations_count ) );
                        } );
    } else {
        std::transform( entropy_distribution_.begin(),
                        entropy_distribution_.end(),
                        distribution_values.begin(),
                        [&]( const auto& v ) {
                            return double( v ) / double( observations_count );
                        } );
    }

    return distribution_values;
} // namespace entropy

void DnsClassifier::set_entropy_distribution( const std::vector<double>& dist,
                                              unsigned weight,
                                              snort::dns_firewall::DistributionScale scale )
{
    dist_bins_ = dist.size();

    // std::vector<unsigned> distribution_values = std::vector<unsigned>( dist_bins_, 0 );
    if( scale == snort::dns_firewall::DistributionScale::LOG ) {

        std::transform(
          dist.begin(), dist.end(), entropy_distribution_.begin(), [&]( const auto& val ) {
              return weight * pow( 10, val );
          } );

    } else {

        std::transform(
          dist.begin(), dist.end(), entropy_distribution_.begin(), [&]( const auto& val ) {
              return weight * val;
          } );
    }
    // for( unsigned i = 0; i < dist_bins_; ++i ) {
    //     if( scale == snort::dns_firewall::DistributionScale::LOG ) {
    //         distribution_values[i] = ;
    //     } else {
    //         distribution_values[i] = weight * dist[i];
    //     }
    // }
    // entropy_distribution_ = distribution_values;
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

        // std::cout << "Fifo, state_shift = " << state_shift_
        //           << ",dns_fifo_.size() = " << dns_fifo_.size() << " metric " <<
        //           current_metric_
        //           << std::endl;

        unsigned distribution_bin = floor( current_metric_ * dist_bins_ );
        ++entropy_distribution_[distribution_bin];
    } else {
        insert( get_dns_xld( domain, 2 ) );
        if( dns_fifo_.size() >= window_width_ ) {
            state_shift_ = true;
        }
    }
}

double DnsClassifier::classify( const std::string& domain ) noexcept
{
    std::string fld = get_dns_xld( domain, 2 );
    if( not state_shift_ ) {
        insert( fld );
        if( dns_fifo_.size() >= window_width_ ) {
            state_shift_ = true;
        }
        return 0;
    }

    forward_shift( fld );
    unsigned distribution_bin = floor( current_metric_ * dist_bins_ );
    unsigned observations_count =
      std::accumulate( entropy_distribution_.begin(), entropy_distribution_.end(), 0 );
    double metric_probability =
      double( entropy_distribution_[distribution_bin] ) / double( observations_count );
    double domain_freq = double( freq_[fld] ) / double( dns_fifo_size_ );
    if( metric_probability < 1e-10 ) {
        return domain_freq * log10( 1 / double( observations_count ) );
    } else {
        return domain_freq * log10( metric_probability );
    }
}

}}} // namespace snort::dns_firewall::entropy
