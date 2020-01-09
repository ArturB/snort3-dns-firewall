#include <algorithm>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <getopt.h>
#include <iostream>
#include <queue>
#include <set>
#include <sstream>
#include <string>
#include <unistd.h>
#include <unordered_map>
#include <vector>

extern char *optarg;

using namespace std;

// Runtime options of the program
class ProgramOptions
{

  public:
    unsigned bins_;
    unsigned window_size_;
    string data_filename_;
    string output_filename_;
    bool log_distribution_;

  public:
    ProgramOptions(int argc, char *const argv[])
        : bins_(1000)
        , window_size_(1000)
        , data_filename_()
        , output_filename_("snort4gini.out")
        , log_distribution_(false)
    {
        int opt;
        while ((opt = getopt(argc, argv, "b:f:w:o:l")) != -1) {
            switch (opt) {
            case 'b':
                bins_ = static_cast<unsigned>(stoi(optarg));
                break;
            case 'f':
                data_filename_ = string(optarg);
                break;
            case 'w':
                window_size_ = static_cast<unsigned>(stoi(optarg));
                break;
            case 'o':
                output_filename_ = string(optarg);
                break;
            case 'l':
                log_distribution_ = true;
                break;
            }
        }
        if (data_filename_.empty()) {
            print_help();
            exit(1);
        }
    }

    void print_help()
    {
        string help =
            "snort4gini usage:\n"
            "   -b: Number of bins when estimating distribution"
            "   -f: File name of the dataset to process (mandatory)\n"
            "   -l: if flag set, the result distribution will be in log "
            "scale (default: no)\n"
            "   -o: Output file name (default: snort4gini.out)\n"
            "   -w: size of shifting window (default: 1000)\n";
        cout << help << endl;
    }
};

// Shifting window, calculating concentration metric in constant memory
class DnsShiftWindow
{

  public:
    queue<string> dns_fifo_; // FIFO queue of processed domains
    unordered_map<string, unsigned>
        freq_; // Mapping from domain to its frequencies in current window
    double current_metric_; // Memoized concentration metric for current window
                            // state
    vector<unsigned>
        distribution_; // Probability distribution of so-far calculated metrics,
                       // stored as number of observations for distribution bins
    unsigned dist_bins_; // Number of bins in metrics distribution

  public:
    // Default constructor
    explicit DnsShiftWindow(const unsigned bins)
        : distribution_(bins, 0)
    {
        dist_bins_ = bins;
        current_metric_ = 0.0;
    }

    // Calculates given metric for one domain
    double domain_metric(const unsigned domain_val)
    {
        if (domain_val == 0) {
            return 0.0;
        } else {
            double domain_freq = double(domain_val) / double(dns_fifo_.size());
            return -1 * domain_freq * log(domain_freq);
        }
    }

    // Calculate given metric for dns_fifo
    double fifo_metric()
    {
        double metric_value = 0;
        for (auto it = freq_.begin(); it != freq_.end(); ++it) {
            // metric_value -= (it->second / n) * log(it->second / n);
            metric_value += domain_metric(it->second);
        }
        return metric_value / log(dns_fifo_.size());
    }

    // Insert new domain to window
    // Updates current_metric value
    void insert(const string &domain)
    {
        dns_fifo_.push(domain);
        ++freq_[domain];
    }

    // Pop domain from window
    // Updates current_metric value
    void pop()
    {
        string domain = dns_fifo_.front();
        // Pop domain
        dns_fifo_.pop();
        --freq_[domain];
        // Remove domain if last occurence deleted
        if (freq_[domain] == 0)
            freq_.erase(domain);
    }

    // Shift window to new domain
    void forward_shift(const string &domain)
    {
        insert(domain);
        pop();
        current_metric_ = fifo_metric();

        unsigned distribution_bin =
            static_cast<unsigned>(floor(current_metric_ * dist_bins_));
        ++distribution_[distribution_bin];
    }

    // Save distribution to file
    void save_distribution(const string &file_name, bool log)
    {
        vector<double> distribution_values = vector<double>(dist_bins_, 0);
        unsigned observations_count = 0;
        for (unsigned i = 0; i < dist_bins_; ++i) {
            observations_count += distribution_[i];
        }

        if (log) {
            for (unsigned i = 0; i < dist_bins_; ++i) {
                ++distribution_[i];
            }
            for (unsigned i = 0; i < dist_bins_; ++i) {
                distribution_values[i] = log10(double(distribution_[i]) /
                                               double(observations_count));
            }
        } else {
            for (unsigned i = 0; i < dist_bins_; ++i) {
                distribution_values[i] =
                    double(distribution_[i]) / double(observations_count);
            }
        }

        ofstream output_file(file_name);
        for (unsigned i = 0; i < dist_bins_; ++i) {
            output_file << distribution_values[i] << endl;
        }
    }
};

// Get first-level DNS domain from string
// E.g. for s2.smtp.google.com function returns google.com
static string GetDnsFld(const string &domain)
{
    string token;
    string fld;
    string tld;
    istringstream domain_ss(domain);
    while (getline(domain_ss, token, '.')) {
        fld = tld;
        tld = token;
    }
    return fld + "." + tld;
}

/**
 * ENTRYPOINT
 */
int main(int argc, char *const argv[])
{
    cout << "snort4gini 0.1.1 by Artur M. Brodzki" << endl;
    ProgramOptions options = ProgramOptions(argc, argv);

    cout << "Dataset file name = " << options.data_filename_ << endl;
    cout << "Window size = " << options.window_size_ << endl;
    cout << "Distribution Bins = " << options.bins_ << endl;
    cout << "Output file name = " << options.output_filename_ << endl;
    if (options.log_distribution_)
        cout << "Generating log-scale distribution..." << endl;

    cout << "Processing data..." << endl;

    ifstream dataset_file(options.data_filename_);
    string line;
    unsigned processed_lines = 0;
    DnsShiftWindow window(options.bins_);

    while (getline(dataset_file, line)) {
        if (processed_lines <= options.window_size_) {
            window.insert(GetDnsFld(line));
        } else {
            window.forward_shift(GetDnsFld(line));
        }
        processed_lines++;
    }

    window.save_distribution(options.output_filename_,
                             options.log_distribution_);
    cout << "Distribution saved to " << options.output_filename_ << "!" << endl;
    cout << "Processed lines: " << processed_lines << endl;
    return 0;
}
