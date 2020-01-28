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

std::ostream& operator<<( std::ostream& os, const Config::Mode& mode )
{
    if( mode == Config::Mode::SIMPLE ) {
        os << "simple";
    }
    if( mode == Config::Mode::LEARN ) {
        os << "learn";
    }
    return os;
}

bool Config::ModelConfig::operator==( const Config::ModelConfig& operand2 ) const
{
    return filename == operand2.filename && weight == operand2.weight;
}

std::ostream& operator<<( std::ostream& os, const Config::ModelConfig& model )
{
    os << "[DNS Firewall]    * file: " << model.filename << std::endl;
    os << "[DNS Firewall]    * weight: " << model.weight;
    return os;
}

bool Config::TimeframeConfig::operator==( const Config::TimeframeConfig& operand2 ) const
{
    return period == operand2.period && max_queries == operand2.max_queries;
}

std::ostream& operator<<( std::ostream& os, const Config::TimeframeConfig& timeframe )
{
    os << "[DNS Firewall]    * period: " << timeframe.period << std::endl;
    os << "[DNS Firewall]    * max-queries: " << timeframe.max_queries;
    return os;
}

bool Config::HmmConfig::operator==( const Config::HmmConfig& operand2 ) const
{
    return weight == operand2.weight;
}

std::ostream& operator<<( std::ostream& os, const Config::HmmConfig& hmm )
{
    os << "[DNS Firewall]    * weight: " << hmm.weight;
    return os;
}

bool Config::EntropyConfig::operator==( const Config::EntropyConfig& operand2 ) const
{
    return weight == operand2.weight;
}

std::ostream& operator<<( std::ostream& os, const Config::EntropyConfig& entropy )
{
    os << "[DNS Firewall]    * weight: " << entropy.weight;
    return os;
}

bool Config::LengthConfig::operator==( const Config::LengthConfig& operand2 ) const
{
    return min_length == operand2.min_length && max_length == operand2.max_length &&
           max_length_penalty == operand2.max_length_penalty;
}

std::ostream& operator<<( std::ostream& os, const Config::LengthConfig& length )
{
    os << "[DNS Firewall]    * min-length: " << length.min_length << std::endl;
    os << "[DNS Firewall]    * max-length: " << length.max_length << std::endl;
    os << "[DNS Firewall]    * max-length-penalty: " << length.max_length_penalty;
    return os;
}

bool Config::RejectConfig::operator==( const Config::RejectConfig& operand2 ) const
{
    return block_period == operand2.block_period && threshold == operand2.threshold &&
           repetitions == operand2.repetitions;
}

std::ostream& operator<<( std::ostream& os, const Config::RejectConfig& reject )
{
    os << "[DNS Firewall]    * block-period: " << reject.block_period << std::endl;
    os << "[DNS Firewall]    * threshold: " << reject.threshold;
    return os;
}

Config::Config( const std::string& config_filename )
{
    YAML::Node node = YAML::LoadFile( config_filename );

    if( node["plugin"]["mode"].as<std::string>() == "simple" ) {
        mode = Config::Mode::SIMPLE;
    }
    if( node["plugin"]["mode"].as<std::string>() == "learn" ) {
        mode = Config::Mode::LEARN;
    }

    model.filename = node["plugin"]["model"]["file"].as<std::string>();
    model.weight   = node["plugin"]["model"]["weight"].as<int>();

    whitelist = node["plugin"]["whitelist"].as<std::string>();
    blacklist = node["plugin"]["blacklist"].as<std::string>();

    timeframe.period      = node["plugin"]["timeframe"]["period"].as<int>();
    timeframe.max_queries = node["plugin"]["timeframe"]["max-queries"].as<int>();

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

bool Config::operator==( const Config& operand2 ) const
{
    return mode == operand2.mode && model == operand2.model &&
           blacklist == operand2.blacklist && whitelist == operand2.whitelist &&
           timeframe == operand2.timeframe && hmm == operand2.hmm &&
           entropy == operand2.entropy && length == operand2.length &&
           short_reject == operand2.short_reject && long_reject == operand2.long_reject &&
           permanent_reject == operand2.permanent_reject;
}

std::ostream& operator<<( std::ostream& os, const Config& options )
{
    os << "[DNS Firewall]  - mode: " << options.mode << std::endl;
    os << "[DNS Firewall]  - Model: " << std::endl;
    os << options.model << std::endl;
    os << "[DNS Firewall]  - blacklist file: " << options.blacklist << std::endl;
    os << "[DNS Firewall]  - whitelist file: " << options.whitelist << std::endl;

    os << "[DNS Firewall]  - Entropy classifier:" << std::endl;
    os << options.entropy << std::endl;
    os << "[DNS Firewall]  - HMM classifier:" << std::endl;
    os << options.hmm << std::endl;
    os << "[DNS Firewall]  - Timeframe classifier:" << std::endl;
    os << options.timeframe << std::endl;

    os << "[DNS Firewall]  - Short reject: " << std::endl;
    os << options.short_reject << std::endl;
    os << "[DNS Firewall]  - Long reject: " << std::endl;
    os << options.long_reject << std::endl;
    os << "[DNS Firewall]  - Permanent reject: " << std::endl;
    os << options.permanent_reject;

    return os;
}

}} // namespace snort::dns_firewall
