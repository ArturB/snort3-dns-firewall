###############################
# Gini distribution generator #
###############################

gini: gini.cc
		g++ -std=c++11 -Wall -O3 gini.cc -o snort4gini

gini-prof: gini.cc
		g++ -std=c++11 -Wall -O3 -pg gini.cc -o snort4gini

gini-clang: gini.cc
		clang++ -Wall -O3 gini.cc -o snort4gini

##########################
# Markov model generator #
##########################

markov: markov.cc
		g++ -std=c++11 -Wall -O3 markov.cc -o snort4markov

markov-prof: markov.cc
		g++ -std=c++11 -Wall -O3 -pg markov.cc -o snort4gini

markov-clang: markov.cc
		clang++ -Wall -O3 markov.cc -o snort4markov
