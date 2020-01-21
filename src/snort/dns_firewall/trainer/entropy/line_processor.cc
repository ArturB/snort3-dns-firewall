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

#include "line_processor.h"

namespace snort
{
namespace dns_firewall
{
namespace trainer
{
namespace entropy
{

LineProcessor::LineProcessor( unsigned window_width, unsigned bins )
    : dns_fifo_size_( 0 )
    , window_width_( window_width )
    , distribution_( bins, 0 )
    , dist_bins_( bins )
    , current_metric_( 0 )
    , processed_lines_( 0 )
{
}

// Calculates given metric for one domain
double LineProcessor::domain_metric( unsigned domain_val ) const
{
    if( domain_val == 0 ) {
        return 0.0;
    } else {
        double domain_freq = double( domain_val ) / double( dns_fifo_size_ );

        return -1 * domain_freq * log( domain_freq );
    }
}

// Calculate given metric for dns_fifo
double LineProcessor::fifo_metric() const
{
    double metric_value = 0;
    for( auto it = freq_.begin(); it != freq_.end(); ++it ) {
        metric_value += domain_metric( it->second );
    }
    return metric_value / log( dns_fifo_.size() );
}

// Insert new domain to window
// Updates current_metric value
void LineProcessor::insert( const std::string& domain )
{
    dns_fifo_.push( domain );
    ++freq_[domain];
    ++dns_fifo_size_;
    current_metric_ = fifo_metric();
}

// Pop domain from window
// Updates current_metric value
void LineProcessor::pop()
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
void LineProcessor::forward_shift( const std::string& domain ) // 53 cycles
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

    unsigned distribution_bin = floor( current_metric_ * dist_bins_ ); // 3 cycles
    ++distribution_[distribution_bin];                                 // 3 cycles
}

void LineProcessor::process_line( const std::string& domain )
{
    if( processed_lines_ < window_width_ ) {
        insert( domain );
    } else {
        forward_shift( domain );
    }
    ++processed_lines_;
}

// Save distribution to file
std::vector<double> LineProcessor::get_distribution( bool log ) const
{
    std::vector<double> distribution_values = std::vector<double>( dist_bins_, 0 );
    unsigned observations_count             = 0;
    for( unsigned i = 0; i < dist_bins_; ++i ) {
        observations_count += distribution_[i];
    }

    if( log ) {
        for( unsigned i = 0; i < dist_bins_; ++i ) {
            distribution_values[i] = distribution_[i] + 1;
        }
        for( unsigned i = 0; i < dist_bins_; ++i ) {
            distribution_values[i] =
              log10( double( distribution_values[i] ) / double( observations_count ) );
        }
    } else {
        for( unsigned i = 0; i < dist_bins_; ++i ) {
            distribution_values[i] = double( distribution_[i] ) / double( observations_count );
        }
    }

    return distribution_values;
}

unsigned LineProcessor::get_window_width() const
{
    return dns_fifo_size_;
}

} // namespace entropy
} // namespace trainer
} // namespace dns_firewall
} // namespace snort
