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

namespace snort { namespace dns_firewall {

bool Config::HmmConfig::operator==( const Config::HmmConfig& operand2 ) const {
    return weight == operand2.weight;
}

bool Config::EntropyConfig::operator==( const Config::EntropyConfig& operand2 ) const {
    return weight == operand2.weight;
}

bool Config::LengthConfig::operator==( const Config::LengthConfig& operand2 ) const {
    return min_length == operand2.min_length && max_length == operand2.max_length &&
           max_length_penalty == operand2.max_length_penalty;
}

bool Config::RejectConfig::operator==( const Config::RejectConfig& operand2 ) const {
    return block_period == operand2.block_period && threshold == operand2.threshold &&
           repetitions == operand2.repetitions;
}

bool Config::operator==( const Config& operand2 ) const {
    return mode == operand2.mode && model_file == operand2.model_file &&
           blacklist == operand2.blacklist && whitelist == operand2.whitelist &&
           hmm == operand2.hmm && entropy == operand2.entropy && length == operand2.length &&
           short_reject == operand2.short_reject && long_reject == operand2.long_reject &&
           permanent_reject == operand2.permanent_reject;
}

Config::Config( const std::string& config_filename ) {
    YAML::Node node = YAML::LoadFile( config_filename );

    if( node["plugin"]["mode"].as<std::string>() == "simple" ) {
        mode = Config::Mode::SIMPLE;
    }
    if( node["plugin"]["mode"].as<std::string>() == "live" ) {
        mode = Config::Mode::LIVE;
    }

    model_file = node["plugin"]["model-file"].as<std::string>();
    whitelist  = node["plugin"]["whitelist"].as<std::string>();
    blacklist  = node["plugin"]["blacklist"].as<std::string>();

    length.min_length         = node["plugin"]["length"]["min-length"].as<int>();
    length.max_length         = node["plugin"]["length"]["max-length"].as<int>();
    length.max_length_penalty = node["plugin"]["length"]["max-length-penalty"].as<double>();

    hmm.weight     = node["plugin"]["hmm"]["weight"].as<int>();
    entropy.weight = node["plugin"]["entropy"]["weight"].as<int>();

    short_reject.block_period = node["plugin"]["short-reject"]["block-period"].as<int>();
    short_reject.threshold    = node["plugin"]["short-reject"]["threshold"].as<int>();
    short_reject.repetitions  = node["plugin"]["short-reject"]["repetitions"].as<int>();

    long_reject.block_period = node["plugin"]["long-reject"]["block-period"].as<int>();
    long_reject.threshold    = node["plugin"]["long-reject"]["threshold"].as<int>();
    long_reject.repetitions  = node["plugin"]["long-reject"]["repetitions"].as<int>();

    permanent_reject.threshold   = node["plugin"]["permanent-reject"]["threshold"].as<int>();
    permanent_reject.repetitions = node["plugin"]["permanent-reject"]["repetitions"].as<int>();
}

}} // namespace snort::dns_firewall
