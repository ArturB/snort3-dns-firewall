add_executable(snort3gini gini.cc)

add_executable(snort3markov markov.cc)
target_link_libraries(snort3markov PUBLIC armadillo)
