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
    switch( mode ) {
    case Config::Mode::SIMPLE:
        os << "simple";
        break;
    case Config::Mode::LEARN:
        os << "learn";
        break;
    }
    return os;
}

std::ostream& operator<<( std::ostream& os, const Config::Verbosity& verbosity )
{
    switch( verbosity ) {
    case Config::Verbosity::ALL:
        os << "all";
        break;
    case Config::Verbosity::ALLOW_ONLY:
        os << "allow only";
        break;
    case Config::Verbosity::REJECT_ONLY:
        os << "reject only";
        break;
    case Config::Verbosity::NONE:
        os << "none";
        break;
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
    return enabled == operand2.enabled && period == operand2.period &&
           max_queries == operand2.max_queries && penalty == operand2.penalty;
}

std::ostream& operator<<( std::ostream& os, const Config::TimeframeConfig& timeframe )
{
    os << "[DNS Firewall]    * enabled: " << ( timeframe.enabled ? "true" : "false" )
       << std::endl;
    os << "[DNS Firewall]    * period: " << timeframe.period << std::endl;
    os << "[DNS Firewall]    * max-queries: " << timeframe.max_queries << std::endl;
    os << "[DNS Firewall]    * penalty: " << timeframe.penalty;
    return os;
}

bool Config::HmmConfig::operator==( const Config::HmmConfig& operand2 ) const
{
    return enabled == operand2.enabled && min_length == operand2.min_length &&
           bias == operand2.bias && weight == operand2.weight;
}

std::ostream& operator<<( std::ostream& os, const Config::HmmConfig& hmm )
{
    os << "[DNS Firewall]    * enabled: " << ( hmm.enabled ? "true" : "false" ) << std::endl;
    os << "[DNS Firewall]    * min-length: " << hmm.min_length << std::endl;
    os << "[DNS Firewall]    * bias: " << hmm.bias << std::endl;
    os << "[DNS Firewall]    * weight: " << hmm.weight;
    return os;
}

bool Config::EntropyConfig::operator==( const Config::EntropyConfig& operand2 ) const
{
    return enabled == operand2.enabled && min_length == operand2.min_length &&
           bias == operand2.bias && weight == operand2.weight;
}

std::ostream& operator<<( std::ostream& os, const Config::EntropyConfig& entropy )
{
    os << "[DNS Firewall]    * enabled: " << ( entropy.enabled ? "true" : "false" )
       << std::endl;
    os << "[DNS Firewall]    * min-length: " << entropy.min_length << std::endl;
    os << "[DNS Firewall]    * bias: " << entropy.bias << std::endl;
    os << "[DNS Firewall]    * weight: " << entropy.weight;
    return os;
}

bool Config::RejectConfig::operator==( const Config::RejectConfig& operand2 ) const
{
    return block_period == operand2.block_period && threshold == operand2.threshold;
}

std::ostream& operator<<( std::ostream& os, const Config::RejectConfig& reject )
{
    os << "[DNS Firewall]    * threshold: " << reject.threshold << std::endl;
    os << "[DNS Firewall]    * block-period: " << reject.block_period;
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

    if( node["plugin"]["verbosity"].as<std::string>() == "all" ) {
        verbosity = Config::Verbosity::ALL;
    }
    if( node["plugin"]["verbosity"].as<std::string>() == "allow-only" ) {
        verbosity = Config::Verbosity::ALLOW_ONLY;
    }
    if( node["plugin"]["verbosity"].as<std::string>() == "reject-only" ) {
        verbosity = Config::Verbosity::REJECT_ONLY;
    }
    if( node["plugin"]["verbosity"].as<std::string>() == "none" ) {
        verbosity = Config::Verbosity::NONE;
    }

    model.filename = node["plugin"]["model"]["file"].as<std::string>();
    model.weight   = node["plugin"]["model"]["weight"].as<int>();

    whitelist = node["plugin"]["whitelist"].as<std::string>();
    blacklist = node["plugin"]["blacklist"].as<std::string>();

    timeframe.enabled     = node["plugin"]["timeframe"]["enabled"].as<bool>();
    timeframe.period      = node["plugin"]["timeframe"]["period"].as<int>();
    timeframe.max_queries = node["plugin"]["timeframe"]["max-queries"].as<int>();
    timeframe.penalty     = node["plugin"]["timeframe"]["penalty"].as<double>();

    hmm.enabled    = node["plugin"]["hmm"]["enabled"].as<bool>();
    hmm.min_length = node["plugin"]["hmm"]["min-length"].as<int>();
    hmm.bias       = node["plugin"]["hmm"]["bias"].as<double>();
    hmm.weight     = node["plugin"]["hmm"]["weight"].as<double>();

    entropy.enabled    = node["plugin"]["entropy"]["enabled"].as<bool>();
    entropy.min_length = node["plugin"]["entropy"]["min-length"].as<int>();
    entropy.bias       = node["plugin"]["entropy"]["bias"].as<double>();
    entropy.weight     = node["plugin"]["entropy"]["weight"].as<double>();

    short_reject.block_period = node["plugin"]["reject"]["block-period"].as<int>();
    short_reject.threshold    = node["plugin"]["reject"]["threshold"].as<double>();
}

bool Config::operator==( const Config& operand2 ) const
{
    return mode == operand2.mode && model == operand2.model &&
           blacklist == operand2.blacklist && whitelist == operand2.whitelist &&
           timeframe == operand2.timeframe && hmm == operand2.hmm &&
           entropy == operand2.entropy && short_reject == operand2.short_reject;
}

std::ostream& operator<<( std::ostream& os, const Config& options )
{
    os << "[DNS Firewall]  - mode: " << options.mode << std::endl;
    os << "[DNS Firewall]  - verbosity: " << options.verbosity << std::endl;
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

    os << "[DNS Firewall]  - Reject config: " << std::endl;
    os << options.short_reject << std::endl;

    return os;
}

}} // namespace snort::dns_firewall
