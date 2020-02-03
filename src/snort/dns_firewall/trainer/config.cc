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

bool Config::DatasetConfig::operator==( const Config::DatasetConfig& operand2 ) const
{
    return filename == operand2.filename && max_lines == operand2.max_lines;
}

std::ostream& operator<<( std::ostream& os, const Config::DatasetConfig& dataset )
{
    os << "   * filename: " << dataset.filename << std::endl;
    os << "   * max-lines: " << dataset.max_lines;
    return os;
}

bool Config::MaxLengthConfig::operator==( const Config::MaxLengthConfig& operand2 ) const
{
    return percentile == operand2.percentile && penalty == operand2.penalty;
}

std::ostream& operator<<( std::ostream& os, const Config::MaxLengthConfig& max_length )
{
    os << "   * percentile: " << max_length.percentile << std::endl;
    os << "   * penalty: " << max_length.penalty;
    return os;
}

bool Config::EntropyConfig::operator==( const Config::EntropyConfig& operand2 ) const
{
    return min_length == operand2.min_length && bins == operand2.bins &&
           scale == operand2.scale && window_widths == operand2.window_widths;
}

std::ostream& operator<<( std::ostream& os, const Config::EntropyConfig& entropy )
{
    os << "   * min length: " << entropy.min_length << std::endl;
    os << "   * distribution bins: " << entropy.bins << std::endl;
    os << "   * distribution scale: " << entropy.scale << std::endl;
    os << "   * window widths: ";
    for( auto& w: entropy.window_widths ) {
        os << w << " ";
    }
    return os;
}

bool Config::HmmConfig::operator==( const Config::HmmConfig& operand2 ) const
{
    return min_length == operand2.min_length && hidden_states == operand2.hidden_states &&
           learning_rate == operand2.learning_rate && batch_size == operand2.batch_size;
}

std::ostream& operator<<( std::ostream& os, const Config::HmmConfig& hmm )
{
    os << "   * min length: " << hmm.min_length << std::endl;
    os << "   * hidden states: " << hmm.hidden_states << std::endl;
    os << "   * learning rate: " << hmm.learning_rate << std::endl;
    os << "   * batch size: " << hmm.batch_size;
    return os;
}

bool Config::operator==( const Config& operand2 ) const
{
    return dataset == operand2.dataset && model_file == operand2.model_file &&
           max_length == operand2.max_length && hmm == operand2.hmm &&
           entropy == operand2.entropy;
}

Config::Config( const std::string& config_filename )
{
    YAML::Node node = YAML::LoadFile( config_filename );

    dataset.filename  = node["trainer"]["dataset"]["filename"].as<std::string>();
    dataset.max_lines = node["trainer"]["dataset"]["max-lines"].as<int>();

    model_file = node["trainer"]["model-file"].as<std::string>();

    max_length.percentile = node["trainer"]["max-length"]["percentile"].as<double>();
    max_length.penalty    = node["trainer"]["max-length"]["penalty"].as<double>();

    hmm.min_length    = node["trainer"]["hmm"]["min-length"].as<int>();
    hmm.hidden_states = node["trainer"]["hmm"]["hidden-states"].as<int>();
    hmm.learning_rate = node["trainer"]["hmm"]["learning-rate"].as<double>();
    hmm.batch_size    = node["trainer"]["hmm"]["batch-size"].as<int>();

    entropy.min_length    = node["trainer"]["entropy"]["min-length"].as<int>();
    entropy.bins          = node["trainer"]["entropy"]["bins"].as<int>();
    std::string log_scale = node["trainer"]["entropy"]["scale"].as<std::string>();
    if( log_scale == "log" ) {
        entropy.scale = snort::dns_firewall::DistributionScale::LOG;
    }
    if( log_scale == "linear" ) {
        entropy.scale = snort::dns_firewall::DistributionScale::LINEAR;
    }

    YAML::Node win_widths = node["trainer"]["entropy"]["window-widths"];
    for( auto&& w: win_widths ) {
        entropy.window_widths.push_back( w.as<int>() );
    }
}

std::ostream& operator<<( std::ostream& os, const Config& options )
{
    os << " - Dataset: " << std::endl;
    os << options.dataset << std::endl;
    os << " - output model file: " << options.model_file << std::endl;
    os << " - Max query length: " << std::endl;
    os << options.max_length << std::endl;
    os << " - Entropy classifier: " << std::endl;
    os << options.entropy << std::endl;
    os << " - HMM classifier: " << std::endl;
    os << options.hmm;
    return os;
}

}}} // namespace snort::dns_firewall::trainer
