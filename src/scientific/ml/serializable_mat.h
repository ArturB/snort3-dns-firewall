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

#ifndef SCIENTIFIC_ML_SERIALIZABLE_MAT_H
#define SCIENTIFIC_ML_SERIALIZABLE_MAT_H

#include <armadillo>
#include <cereal/archives/binary.hpp>
#include <cereal/types/polymorphic.hpp>
#include <cereal/types/string.hpp>
#include <cereal/types/unordered_map.hpp>
#include <cereal/types/vector.hpp>
#include <vector>

namespace scientific { namespace ml {

struct SerializableMat
{
    arma::mat m;

    SerializableMat()
    {
    }
    explicit SerializableMat( const arma::mat m )
        : m( m )
    {
    }

    // Serialize armadillo
    template<class Archive>
    void save( Archive& archive ) const
    {
        unsigned n_rows = m.n_rows;
        unsigned n_cols = m.n_cols;
        std::vector<double> m_vectorized;

        for( unsigned i = 0; i < n_rows; ++i ) {
            for( unsigned j = 0; j < n_cols; ++j ) {
                m_vectorized.push_back( m( i, j ) );
            }
        }

        archive( n_rows, n_cols, m_vectorized );
    }

    // Deserialize armadillo
    template<class Archive>
    void load( Archive& archive )
    {
        unsigned n_rows;
        unsigned n_cols;
        std::vector<double> m_vectorized;

        archive( n_rows, n_cols, m_vectorized );

        arma::mat m2( n_rows, n_cols );
        for( unsigned i = 0; i < n_rows; ++i ) {
            for( unsigned j = 0; j < n_cols; ++j ) {
                m2( i, j ) = m_vectorized[i * n_cols + j];
            }
        }
        m = m2;
    }
};

}} // namespace scientific::ml

#endif // SCIENTIFIC_ML_SERIALIZABLE_MAT_H