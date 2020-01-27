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
#include <yaml-cpp/yaml.h>

namespace snort { namespace dns_firewall { namespace trainer {

bool Config::EntropyConfig::operator==( const Config::EntropyConfig& operand2 ) const
{
    return bins == operand2.bins && scale == operand2.scale &&
           window_widths == operand2.window_widths;
}

std::ostream& operator<<( std::ostream& os, const Config::EntropyConfig& entropy )
{
    os << "   * distribution bins: " << entropy.bins << std::endl;
    os << "   * distribution scale: " << entropy.scale << std::endl;
    os << "   * window widths: ";
    for( auto it = entropy.window_widths.begin(); it != entropy.window_widths.end(); ++it ) {
        os << *it << " ";
    }
    return os;
}

bool Config::HmmConfig::operator==( const Config::HmmConfig& operand2 ) const
{
    return hidden_states == operand2.hidden_states;
}

std::ostream& operator<<( std::ostream& os, const Config::HmmConfig& hmm )
{
    os << "   * hidden states: " << hmm.hidden_states;
    return os;
}

bool Config::operator==( const Config& operand2 ) const
{
    return dataset == operand2.dataset && model_file == operand2.model_file &&
           max_lines == operand2.max_lines && hmm == operand2.hmm &&
           entropy == operand2.entropy;
}

Config::Config( const std::string& config_filename )
{
    YAML::Node node = YAML::LoadFile( config_filename );

    dataset    = node["trainer"]["dataset"].as<std::string>();
    model_file = node["trainer"]["model-file"].as<std::string>();
    max_lines  = node["trainer"]["max-lines"].as<int>();

    hmm.hidden_states = node["trainer"]["hmm"]["hidden-states"].as<int>();

    entropy.bins = node["trainer"]["entropy"]["bins"].as<int>();

    std::string log_scale = node["trainer"]["entropy"]["scale"].as<std::string>();
    if( log_scale == "log" ) {
        entropy.scale = snort::dns_firewall::DistributionScale::LOG;
    } else {
        entropy.scale = snort::dns_firewall::DistributionScale::LINEAR;
    }

    YAML::Node win_widths = node["trainer"]["entropy"]["window-widths"];
    for( auto it = win_widths.begin(); it != win_widths.end(); ++it ) {
        entropy.window_widths.push_back( it->as<int>() );
    }
}

std::ostream& operator<<( std::ostream& os, const Config& options )
{
    os << " - dataset file: " << options.dataset << std::endl;
    os << " - output model file: " << options.model_file << std::endl;
    os << " - max lines processed: " << options.max_lines << std::endl;
    os << " - Entropy classifier: " << std::endl;
    os << options.entropy << std::endl;
    os << " - HMM classifier: " << std::endl;
    os << options.hmm;
    return os;
}

}}} // namespace snort::dns_firewall::trainer
