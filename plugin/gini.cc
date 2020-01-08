#include <cstdlib>
#include <cstdio>
#include <iostream>
#include <fstream>
#include <unistd.h>
#include <getopt.h>
#include <queue>
#include <string.h>
#include <unordered_map>
#include <cmath>
#include <set>
#include <algorithm>
#include <sstream>
#include <vector>

using namespace std;

class DnsShiftWindow {

public:

    queue<string> dns_fifo_  ;       // FIFO queue of processed domains
    unordered_map<string,int> freq_; // Mapping from domain to its frequencies in current window
    double current_metric_;          // Memoized concentration metric for current window state
    vector<double> distribution_;    // Probability distribution of so-far calculated metrics
    unsigned int dist_bins_;

public:

    // Default constructor
    DnsShiftWindow(const unsigned int bins) {
        distribution_ = vector<double>(bins, 0);
        dist_bins_ = bins;
        current_metric_ = 0.0;
    }

    // Calculates given metric for one domain
    double domain_metric(int domain_val) {
        if(domain_val == 0) {
            return 0.0;
        }
        else {
            double domain_freq = double(domain_val) / double(dns_fifo_.size());
        return -1 * domain_freq * log(domain_freq);
        }
    }

    // Calculate given metric for dns_fifo
    double fifo_metric() {
        double metric_value = 0; double n = dns_fifo_.size();
        for(auto it = freq_.begin(); it != freq_.end(); ++it) {
            //metric_value -= (it->second / n) * log(it->second / n);
            metric_value += domain_metric(it->second);
        }
        return metric_value / log(dns_fifo_.size());
    }

    // Insert new domain to window
    // Updates current_metric value 
    void insert(const string& domain) {
        dns_fifo_.push(domain);
        ++freq_[domain];
    }

    // Pop domain from window
    // Updates current_metric value 
    void pop() {
        string domain = dns_fifo_.front();
        // Pop domain
        dns_fifo_.pop();
        --freq_[domain];
        // Remove domain if last occurence deleted
        if (freq_[domain] <= 0)
            freq_.erase(domain);
    }

    // Shift window to new domain
    void forward_shift(const string& domain) {
        insert(domain); pop(); current_metric_ = fifo_metric();

        int distribution_bin = floor(current_metric_ * dist_bins_);
        ++distribution_[distribution_bin];
    }

    // Save distribution to file
    void save_distribution(string file_name, bool log) {
        vector<double> distribution_values = vector<double>(dist_bins_, 0);
        int observations_count = 0;
        for(unsigned int i = 0; i < dist_bins_; ++i) {
                observations_count += distribution_[i];
        }

        if(log) {
            for(unsigned int i = 0; i < dist_bins_; ++i) {
                ++distribution_[i];
            }
            for(unsigned int i = 0; i < dist_bins_; ++i) {
                distribution_values[i] = log10(distribution_[i] / observations_count);
            }
        } else {
            for(unsigned int i = 0; i < dist_bins_; ++i) {
                distribution_values[i] = round(100 * dist_bins_ * distribution_[i] / observations_count);
            }
        }

        ofstream output_file(file_name);
        for(unsigned int i = 0; i < dist_bins_; ++i) {
            output_file << distribution_values[i] << endl;
        }
    }

};

extern char *optarg;

// Get first-level DNS domain from string
// E.g. for s2.smtp.google.com function returns google.com
static string GetDnsFld(const string& domain) {
    string token; string fld; string tld;
    istringstream domain_ss(domain);
    while( getline(domain_ss, token, '.') ) {
        fld = tld;
        tld = token;
    }
    return fld + "." + tld;
};

/**
 * ENTRYPOINT
 */
int main(int argc, char* const argv[]) {
    cout << "snort2dns 0.1.1 by Artur M. Brodzki" << endl; 
    /**
     * Parse command line arguments
     */
    int opt;
    string dataset_filename = "";
    int window_size = 1024;
    string output_filename = "";
    while( (opt = getopt(argc,argv,"f:w:o:")) != -1 ) {
        switch(opt) {
        case 'f': 
            dataset_filename = string(optarg);
            cout << "Dataset file name = " << dataset_filename << endl;
            break;
        case 'w': 
            window_size = stoi(optarg);
            cout << "Window size = " << window_size << endl;
            break;
        case 'o':
            output_filename = string(optarg);
            cout << "Output file name = " << output_filename << endl;
        }
    }
    cout << "Processing data..." << endl << endl;
    /**
     * Open and process data file
     */
    ifstream dataset_file(dataset_filename);
    string line; int processed_lines = 0;
    DnsShiftWindow window(1000);

    while( getline(dataset_file, line) ) {
        if(processed_lines <= window_size) {
            window.insert(GetDnsFld(line));
        }
        else {
            window.forward_shift(GetDnsFld(line));
        }
        processed_lines++;
    }

    cout << "Processed lines: " << processed_lines << endl; 
    window.save_distribution(output_filename, true);
    return 0;
}
