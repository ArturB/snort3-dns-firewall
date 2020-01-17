add_executable(snort3gini gini.cc)
install (
    TARGETS snort3gini
    RUNTIME DESTINATION "lib64/snort/${CMAKE_PROJECT_NAME}"
)

add_executable(snort3markov markov.cc)
target_link_libraries(snort3markov PUBLIC armadillo)
install (
    TARGETS snort3markov
    RUNTIME DESTINATION "lib64/snort/${CMAKE_PROJECT_NAME}"
)
