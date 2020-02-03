// **********************************************************************
// Copyright (c) Artur M. Brodzki 2020. All rights reserved.
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

#ifndef SCIENTIFIC_ML_SMART_HMM_H
#define SCIENTIFIC_ML_SMART_HMM_H

#include "serializable_mat.h"
#include <algorithm>
#include <armadillo>
#include <cereal/archives/binary.hpp>
#include <cereal/types/polymorphic.hpp>
#include <cereal/types/string.hpp>
#include <cereal/types/unordered_map.hpp>
#include <cereal/types/vector.hpp>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <limits>
#include <mutex>
#include <sstream>
#include <string>
#include <unistd.h>
#include <unordered_map>
#include <vector>

namespace scientific { namespace ml {

// S - type representing sequence generated by HMM
// E - type representing one element of that sequence
// For most cases, S will be string, and E will be char
template<class E, class S>
class Hmm
{
  public:
    struct Path
    {
        std::vector<unsigned> states;
        S sequence;
        double prob;
        Path()
            : prob( 0 )
        {
        }

        // Print Path object to stream
        friend std::ostream& operator<<( std::ostream& os,
                                         typename Hmm<E, S>::Path const& path )
        {
            os << "sequence: " << path.sequence << ", states = ";
            for( auto s: path.states ) {
                os << s << " ";
            }
            os << ", prob = " << path.prob;
            return os;
        }
    };

  private:
    unsigned current_state;
    arma::mat initial_states;
    arma::mat initial_states_prim;
    arma::mat transitions;
    arma::mat transitions_prim;
    arma::mat emissions;
    arma::mat emissions_prim;
    S alphabet;
    unsigned processed_lines;
    std::vector<S> learning_buffer;
    std::mutex mutex;

    // Normalize given matrix in rows
    arma::mat normalize_rows( const arma::mat& ) const;
    // Normalize transitions and emissions matrices
    void normalize();
    // Return internal index of given output character
    unsigned out_index( E ) const;
    // Given vector of N probabilities (summing up to 1),
    // function returns unsigned from 0 to N-1
    // according to specified probabilities distribution
    static unsigned random_element( const arma::mat& );

  public:
    // Default contructor- assumes 0 states with empty alphaber
    // Requires loading HMM object from file (serialization) before use
    Hmm();
    // Copy constructor
    Hmm( const Hmm& );
    // Assumes random, uniformly distributed probabilities for transitions and emissions
    Hmm( unsigned num_states, const S& );
    // Construct an HMM object with given transitions and emissions probabilities
    // Transition and emission probabilities are scaled down to sum 1
    Hmm( const arma::mat& transitions,
         const arma::mat& emissions,
         const arma::mat& initial_state,
         const S& );

    // Get possible outputs
    S get_alphabet() const;
    // Get vector of HMM states
    std::vector<unsigned> get_states() const;
    // Get current HMM state
    unsigned get_current_state() const;
    // Set current HMM state
    void set_current_state( unsigned );
    // Get vector of initial states probabilities
    arma::mat get_initial_states() const;
    // Set initial states vector
    void set_initial_states( const arma::mat& );
    // Get emissions probability
    double get_emission( unsigned, E ) const;
    // Get transitions probability
    double get_transition( unsigned state_from, unsigned state_to ) const;

    // Move HMM machine to the next state and return an output char,
    // according to current transitions and emissions probabilities.
    // Returns output char and probability of transition
    std::pair<E, double> next_step();
    // Generate random sequence with specified length
    Path generate_sequence( unsigned );
    // Generate random sequence up to given output value
    Path generate_sequence( E end_char );
    // Find Viterbi path for given sequence
    Path find_viterbi_path( const S& sequence );
    // Learn HMM utilizing Baum-Welch algorithm
    // If update = false, transitions and emissions matrices
    // are not instantly updated, but rather learning state
    // is accumulated in *_prim matrices, and then applied
    // when calling update() method
    void learn( const S& sequence, double, unsigned batch_size );
    void learn_parallel( const S& sequence, double, unsigned batch_size );
    // Update transitions and emisisons matrices
    // with accumulated learning state
    void update( double );

    // Serialization
    template<class Archive>
    void save( Archive& archive ) const;
    template<class Archive>
    void load( Archive& archive );

    void save_to_file( const std::string& ) const;
    void load_from_file( const std::string& );

    // Assignment operator
    // As mutex field is present in the class,
    // assigmnent operator must be explicitly defined
    Hmm<E, S>& operator=( const Hmm<E, S>& );
    // Comparison operator
    bool operator==( const Hmm<E, S>& ) const;

    // Print HMM object to stream
    friend std::ostream& operator<<( std::ostream& os, const Hmm<E, S>& h )
    {
        os << "Transitions: " << std::endl
           << h.transitions << std::endl
           << "Emissions: " << std::endl
           << h.emissions << std::endl
           << "Inirial states: " << h.initial_states;
        return os;
    }

}; // class Hmm

// *************
// CONSTRUCTORS
// *************

// Default contructor- assumes 0 states with empty alphaber
// Requires loading HMM object from file (serialization) before use
template<class E, class S>
Hmm<E, S>::Hmm()
{
}

// Copy constructor
template<class E, class S>
Hmm<E, S>::Hmm( const Hmm<E, S>& hmm )
    : current_state( hmm.current_state )
    , initial_states( hmm.initial_states )
    , initial_states_prim( hmm.initial_states_prim )
    , transitions( hmm.transitions )
    , transitions_prim( hmm.transitions_prim )
    , emissions( hmm.emissions )
    , emissions_prim( hmm.emissions_prim )
    , alphabet( hmm.alphabet )
    , processed_lines( hmm.processed_lines )
    , learning_buffer( hmm.learning_buffer )
{
}

// Assumes random probability distribution for transitions and emissions
template<class E, class S>
Hmm<E, S>::Hmm( unsigned num_states, const S& alphabet )
    : current_state( 0 )
    , initial_states( arma::randu<arma::mat>( 1, num_states ) )
    , initial_states_prim( 1, num_states )
    , transitions( arma::randu<arma::mat>( num_states, num_states ) )
    , transitions_prim( num_states, num_states )
    , emissions( arma::randu<arma::mat>( num_states, alphabet.size() ) )
    , emissions_prim( num_states, alphabet.size() )
    , alphabet( alphabet )
    , processed_lines( 0 )
{
    normalize();
    initial_states_prim.fill( 0 );
    transitions_prim.fill( 0 );
    emissions_prim.fill( 0 );
    current_state = random_element( initial_states );
}

// Construct an HMM object with given transitions and emissions probabilities
// Transition and emission probabilities are scaled down to sum 1
template<class E, class S>
Hmm<E, S>::Hmm( const arma::mat& transitions,
                const arma::mat& emissions,
                const arma::mat& initial_states,
                const S& alphabet )
    : initial_states( initial_states )
    , initial_states_prim( initial_states )
    , transitions( transitions )
    , transitions_prim( transitions )
    , emissions( emissions )
    , emissions_prim( emissions )
    , alphabet( alphabet )
    , processed_lines( 0 )
{
    bool valid_sizes =
      initial_states.n_cols == transitions.n_cols && transitions.n_rows == transitions.n_cols &&
      transitions.n_rows == emissions.n_rows && emissions.n_cols == alphabet.size();
    if( not valid_sizes ) {
        throw std::invalid_argument( "Transmission and/or emissions matrix size invalid! " +
                                     std::to_string( (unsigned) transitions.n_rows ) + ", " +
                                     std::to_string( (unsigned) transitions.n_cols ) + ", " +
                                     std::to_string( (unsigned) emissions.n_rows ) + ", " +
                                     std::to_string( (unsigned) emissions.n_cols ) );
    }

    normalize();
    initial_states_prim.fill( 0 );
    transitions_prim.fill( 0 );
    emissions_prim.fill( 0 );
}

// ******************
// GETTERS & SETTERS
// ******************

// Get possible outputs
template<class E, class S>
std::vector<unsigned> Hmm<E, S>::get_states() const
{
    std::vector<unsigned> result;
    for( unsigned i = 0; i < transitions.n_rows; ++i ) {
        result.push_back( i );
    }
    return result;
}

// Get vector of HMM states
template<class E, class S>
S Hmm<E, S>::get_alphabet() const
{
    return alphabet;
}

// Get initial states probabilities
template<class E, class S>
arma::mat Hmm<E, S>::get_initial_states() const
{
    return initial_states;
}

// Set initial states probabilities
template<class E, class S>
void Hmm<E, S>::set_initial_states( const arma::mat& initial_states_ )
{
    if( initial_states.n_cols != initial_states_.n_cols ) {
        throw std::invalid_argument( "Vector of initial probabilities is of invalid length!" );
    }
    initial_states = initial_states_;
}

// Get emission probability
template<class E, class S>
double Hmm<E, S>::get_emission( unsigned state, E e ) const
{
    unsigned i = 0;
    for( i = 0; i < alphabet.size(); ++i ) {
        if( alphabet[i] == e ) {
            break;
        }
    }
    return emissions( state, i );
}

// Get transition probability
template<class E, class S>
double Hmm<E, S>::get_transition( unsigned state_from, unsigned state_to ) const
{
    return transitions( state_from, state_to );
}

// Get current HMM state
template<class E, class S>
unsigned Hmm<E, S>::get_current_state() const
{
    return current_state;
}

// Set current HMM state
template<class E, class S>
void Hmm<E, S>::set_current_state( unsigned state )
{
    if( state > get_states().back() ) {
        throw std::out_of_range();
    }
    current_state = state;
}

// ****************
// PRIVATE MEMBERS
// ****************

// Normalize given matrix in rows
template<class E, class S>
arma::mat Hmm<E, S>::normalize_rows( const arma::mat& mat ) const
{
    // Scale given probabilities to sum 1 for each state
    arma::mat result( mat );
    arma::mat sums = arma::sum( mat, 1 );
    for( unsigned i = 0; i < mat.n_rows; ++i ) {
        for( unsigned j = 0; j < mat.n_cols; ++j ) {
            result( i, j ) = mat( i, j ) / sums( i );
        }
    }
    return result;
}

// Normalize transitions and emissions matrices
template<class E, class S>
void Hmm<E, S>::normalize()
{
    // Scale given probabilities to sum 1 for each state
    transitions    = normalize_rows( transitions );
    emissions      = normalize_rows( emissions );
    initial_states = normalize_rows( initial_states );
}

// Auxiliary function
// Given vector of N probabilities (summing up to 1),
// function returns unsigned from 0 to N-1
// according to specified probabilities distribution
template<class E, class S>
unsigned Hmm<E, S>::random_element( const arma::mat& probabilities )
{
    const int rand_precision = 1073741824;
    double seed              = double( rand() % rand_precision ) / rand_precision;
    unsigned i               = 0;
    while( seed >= probabilities( i ) && i < probabilities.n_elem ) {
        seed -= probabilities( i );
        ++i;
    }
    return i;
}

// Return internal index of given output character
template<class E, class S>
unsigned Hmm<E, S>::out_index( E e ) const
{
    unsigned i = 0;
    for( i = 0; i < alphabet.size(); ++i ) {
        if( alphabet[i] == e ) {
            break;
        }
    }
    if( i >= alphabet.size() ) {
        throw std::invalid_argument( "Given character is not in HMM alphabet!" );
    }
    return i;
}

// ***************
// PUBLIC MEMBERS
// ***************

// Move HMM machine to the next state and return an output char,
// according to current transitions and emissions probabilities.
// Returns output char and probability of transition
template<class E, class S>
std::pair<E, double> Hmm<E, S>::next_step()
{
    arma::mat current_transitions = transitions.row( current_state );
    arma::mat current_emissions   = emissions.row( current_state );

    unsigned new_state     = random_element( current_transitions );
    double new_state_prob  = transitions( current_state, new_state );
    E new_output           = alphabet[random_element( current_emissions )];
    double new_output_prob = get_emission( current_state, new_output );

    current_state = new_state;

    return std::make_pair( new_output, log10( new_state_prob ) + log10( new_output_prob ) );
}

// Generate random sequence with specified length
template<class E, class S>
typename Hmm<E, S>::Path Hmm<E, S>::generate_sequence( unsigned sequence_length )
{
    normalize();
    current_state = random_element( initial_states );
    Hmm<E, S>::Path result;
    for( unsigned i = 0; i < sequence_length; ++i ) {
        result.states.push_back( current_state );
        auto next = Hmm<E, S>::next_step();
        result.sequence.push_back( next.first );
        result.prob += next.second;
    }
    return result;
}

// Generate random sequence up to given output value
template<class E, class S>
typename Hmm<E, S>::Path Hmm<E, S>::generate_sequence( E end )
{
    normalize();
    current_state = random_element( initial_states );
    Hmm<E, S>::Path result;
    while( result.sequence.back() != end ) {
        result.states.push_back( current_state );
        auto next = Hmm<E, S>::next_step();
        result.sequence.push_back( next.first );
        result.prob += next.second;
    }
    return result;
}

// Find Viterbi path for given sequence and initial state probabilities
template<class E, class S>
typename Hmm<E, S>::Path Hmm<E, S>::find_viterbi_path( const S& sequence )
{
    unsigned num_states = get_states().size();

    arma::mat t1( num_states, sequence.size() ); // t1( i, t ) is probability of most likely
                                                 // path generating sequence from seq(0) to
                                                 // seq(t), ending in state i
    arma::mat t2( num_states, sequence.size() ); // t2 ( i, t ) is element i of most likely
                                                 // path generating sequence from seq(0) to
                                                 // seq(t) and ending in state i

    // Dynamically fill tables
    for( unsigned t = 0; t < sequence.size(); ++t ) {
        for( unsigned i = 0; i < num_states; ++i ) {
            if( t == 0 ) {
                t1( i, t ) = get_emission( i, sequence[t] ) * initial_states( i );
                t2( i, t ) = 0;
            } else {
                double valmax = 0;
                double argmax = 0;
                for( unsigned k = 0; k < num_states; ++k ) {
                    double val =
                      t1( k, t - 1 ) * get_emission( i, sequence[t] ) * get_transition( k, i );
                    if( val > valmax ) {
                        valmax = val;
                        argmax = k;
                    }
                }
                t1( i, t ) = valmax;
                t2( i, t ) = argmax;
            }
        } // for unsigned i
    }     // for unsigned t

    // Calculate final path
    arma::umat z( 1, sequence.size() );
    for( unsigned t = sequence.size() - 1; t > 0; --t ) {
        if( t == sequence.size() - 1 ) {
            double zmax    = 0;
            double zargmax = 0;
            for( unsigned k = 0; k < num_states; ++k ) {
                if( t1( k, sequence.size() - 1 ) > zmax ) {
                    zmax    = t1( k, sequence.size() - 1 );
                    zargmax = k;
                }
            }
            z( t ) = zargmax;
        } else {
            z( t ) = t2( z( t + 1 ), t + 1 );
        }
    }
    z( 0 ) = t2( z( 1 ), 1 );

    // Return result: convert arma::mat to vector<unsigned>
    Hmm<E, S>::Path result;
    result.sequence = sequence;
    for( unsigned t = 0; t < sequence.size(); ++t ) {
        result.states.push_back( z( t ) );
        if( t == 0 ) {
            result.prob =
              log10( initial_states( z( t ) ) ) + log10( get_emission( z( t ), sequence[t] ) );
        } else {
            result.prob += log10( get_emission( z( t ), sequence[t] ) ) +
                           log10( get_transition( z( t - 1 ), z( t ) ) );
        }
    }
    return result;

} // Hmm::find_viterbi_path

// Learn HMM utilizing Brodzki-Viterbi algorithm
template<class E, class S>
void Hmm<E, S>::learn( const S& sequence, double learn_rate, unsigned batch_size )
{
    Path best_path = find_viterbi_path( sequence );
    for( unsigned i = 0; i < sequence.size() - 1; ++i ) {
        transitions_prim( best_path.states[i], best_path.states[i + 1] )++;
    }
    for( unsigned i = 0; i < sequence.size(); ++i ) {
        emissions_prim( best_path.states[i], out_index( sequence[i] ) )++;
    }
    initial_states_prim( best_path.states[0] )++;

    mutex.lock();
    ++processed_lines;
    if( processed_lines % batch_size == 0 ) {
        update( learn_rate );
    }
    mutex.unlock();
} // Hmm::learn

template<class E, class S>
void Hmm<E, S>::learn_parallel( const S& sequence, double learn_rate, unsigned batch_size )
{
    learning_buffer.push_back( sequence );
    const unsigned NUM_THREADS       = 8;
    const unsigned THREAD_BATCH_SIZE = batch_size / NUM_THREADS;

    if( learning_buffer.size() == batch_size ) {

        // Parallel threads work
#pragma omp parallel for
        for( unsigned i = 0; i < NUM_THREADS; ++i ) {

            // One thread
            for( unsigned j = 0; j < THREAD_BATCH_SIZE; ++j ) {
                learn( learning_buffer[i * THREAD_BATCH_SIZE + j], learn_rate, batch_size );
            }
        }
        learning_buffer.clear();
    } // if
}

// Update transitions and emisisons matrices
// with accumulated learning state
template<class E, class S>
void Hmm<E, S>::update( double learn_rate )
{
    transitions += learn_rate * transitions_prim;
    emissions += learn_rate * emissions_prim;
    initial_states += learn_rate * initial_states_prim;
    normalize();
    transitions_prim.fill( 0 );
    emissions_prim.fill( 0 );
    initial_states_prim.fill( 0 );
}

// **********************
// SERIALIZATION METHODS
// **********************

// Serialize HMM
template<class E, class S>
template<class Archive>
void Hmm<E, S>::save( Archive& archive ) const
{
    SerializableMat initial_states_serializable( initial_states );
    SerializableMat initial_states_prim_serializable( initial_states_prim );
    SerializableMat transitions_serializable( transitions );
    SerializableMat transitions_prim_serializable( transitions_prim );
    SerializableMat emissions_serializable( emissions );
    SerializableMat emissions_prim_serializable( emissions_prim );

    archive( current_state,
             initial_states_serializable,
             initial_states_prim_serializable,
             transitions_serializable,
             transitions_prim_serializable,
             emissions_serializable,
             emissions_prim_serializable,
             alphabet,
             processed_lines,
             learning_buffer );
}

template<class E, class S>
template<class Archive>
void Hmm<E, S>::load( Archive& archive )
{
    SerializableMat initial_states_serializable;
    SerializableMat initial_states_prim_serializable;
    SerializableMat transitions_serializable;
    SerializableMat transitions_prim_serializable;
    SerializableMat emissions_serializable;
    SerializableMat emissions_prim_serializable;

    archive( current_state,
             initial_states_serializable,
             initial_states_prim_serializable,
             transitions_serializable,
             transitions_prim_serializable,
             emissions_serializable,
             emissions_prim_serializable,
             alphabet,
             processed_lines,
             learning_buffer );

    initial_states      = initial_states_serializable.m;
    initial_states_prim = initial_states_prim_serializable.m;
    transitions         = transitions_serializable.m;
    transitions_prim    = transitions_prim_serializable.m;
    emissions           = emissions_serializable.m;
    emissions_prim      = emissions_prim_serializable.m;
}

template<class E, class S>
void Hmm<E, S>::save_to_file( const std::string& filename ) const
{
    std::ofstream fs( filename );
    cereal::BinaryOutputArchive oarchive( fs );
    oarchive( *this );
    fs.close();
}

template<class E, class S>
void Hmm<E, S>::load_from_file( const std::string& filename )
{
    std::ifstream fs( filename );
    cereal::BinaryInputArchive iarchive( fs );
    iarchive( *this );
    fs.close();
}

// *****************
// COMMON OPERATORS
// *****************

// Assignment operator
// As mutex field is present in the class,
// assigmnent operator must be explicitly defined
template<class E, class S>
Hmm<E, S>& Hmm<E, S>::operator=( const Hmm<E, S>& hmm )
{
    current_state       = hmm.current_state;
    initial_states      = hmm.initial_states;
    initial_states_prim = hmm.initial_states_prim;
    transitions         = hmm.transitions;
    transitions_prim    = hmm.transitions_prim;
    emissions           = hmm.emissions;
    emissions_prim      = hmm.emissions_prim;
    alphabet            = hmm.alphabet;
    processed_lines     = hmm.processed_lines;
    learning_buffer     = hmm.learning_buffer;

    return *this;
}

// Comparison operator
template<class E, class S>
bool Hmm<E, S>::operator==( const Hmm<E, S>& operand2 ) const
{
    return current_state == operand2.current_state &&
           arma::approx_equal( initial_states, operand2.initial_states, "absdiff", 0.0001 ) &&
           arma::approx_equal(
             initial_states_prim, operand2.initial_states_prim, "absdiff", 0.0001 ) &&
           arma::approx_equal( transitions, operand2.transitions, "absdiff", 0.0001 ) &&
           arma::approx_equal(
             transitions_prim, operand2.transitions_prim, "absdiff", 0.0001 ) &&
           arma::approx_equal( emissions, operand2.emissions, "absdiff", 0.0001 ) &&
           arma::approx_equal( emissions_prim, operand2.emissions_prim, "absdiff", 0.0001 ) &&
           alphabet == operand2.alphabet && processed_lines == operand2.processed_lines;
}
}} // namespace scientific::ml

// CEREAL_REGISTER_TYPE( scientific::ml::Hmm<char, std::string> )

#endif // SCIENTIFIC_ML_SMART_HMM_H

// unsigned current_state;
// arma::mat initial_states;
// arma::mat initial_states_prim;
// arma::mat transitions;
// arma::mat transitions_prim;
// arma::mat emissions;
// arma::mat emissions_prim;
// S alphabet;
// unsigned processed_lines;
// std::vector<S> learning_buffer;
// std::mutex mutex;