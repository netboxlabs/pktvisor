/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include <csignal>
#include <functional>
#include <map>

#include <docopt/docopt.h>

#include "CoreRegistry.h"
#include "HandlerManager.h"
#include "InputStreamManager.h"
#include <spdlog/sinks/stdout_color_sinks.h>

#include "visor_config.h"

#include "GeoDB.h"
#include "handlers/dhcp/DhcpStreamHandler.h"
#include "handlers/dns/v1/DnsStreamHandler.h"
#include "handlers/net/v1/NetStreamHandler.h"
#include "inputs/dnstap/DnstapInputStream.h"
#include "inputs/flow/FlowInputStream.h"
#include "inputs/pcap/PcapInputStream.h"

static const char USAGE[] =
    R"(pktvisor-reader
    Usage:
      pktvisor-reader [options] FILE
      pktvisor-reader (-h | --help)
      pktvisor-reader --version

    Summarize a network (pcap, dnstap) file. The result will be written to stdout in JSON format, while console logs will be printed
    to stderr.

    Options:
      -i INPUT              Input type (pcap|dnstap|sflow|netflow). If not set, default is pcap input
      --max-deep-sample N   Never deep sample more than N% of streams (an int between 0 and 100) [default: 100]
      --periods P           Hold this many 60 second time periods of history in memory. Use 1 to summarize all data. [default: 5]
      -h --help             Show this screen
      --version             Show version
      -v                    Verbose log output
      -b BPF                Filter packets using the given BPF string
      --geo-city FILE       GeoLite2 City database to use for IP to Geo mapping (if enabled)
      --geo-asn FILE        GeoLite2 ASN database to use for IP to ASN mapping (if enabled)
      -H HOSTSPEC           Specify subnets (comma separated) to consider HOST, in CIDR form. In live capture this /may/ be detected automatically
                            from capture device but /must/ be specified for pcaps. Example: "10.0.1.0/24,10.0.2.1/32,2001:db8::/64"
                            Specifying this for live capture will append to any automatic detection.
)";

namespace {
std::function<void(int)> shutdown_handler;
void signal_handler(int signal)
{
    shutdown_handler(signal);
}
}

using namespace visor;

enum InputType {
    PCAP = 0,
    DNSTAP = 1,
    SFLOW = 2,
    NETFLOW = 3,
};

static const std::map<std::string, InputType> input_map = {
    {"pcap", PCAP},
    {"dnstap", DNSTAP},
    {"sflow", SFLOW},
    {"netflow", NETFLOW}};

void initialize_geo(const docopt::value &city, const docopt::value &asn)
{
    if (city) {
        geo::GeoIP().enable(city.asString());
    }
    if (asn) {
        geo::GeoASN().enable(asn.asString());
    }
}

int main(int argc, char *argv[])
{
    int result{0};

    std::map<std::string, docopt::value> args = docopt::docopt(USAGE,
        {argv + 1, argv + argc},
        true,           // show help if requested
        VISOR_VERSION); // version string

    auto logger = spdlog::stderr_color_mt("visor");
    if (args["-v"].asBool()) {
        logger->set_level(spdlog::level::debug);
    }

    CoreRegistry registry;

    std::signal(SIGINT, signal_handler);
    std::signal(SIGTERM, signal_handler);

    int sample_rate = 100;
    if (args["--max-deep-sample"]) {
        sample_rate = (int)args["--max-deep-sample"].asLong();
        if (sample_rate != 100) {
            logger->info("Using maximum deep sample rate: {}%", sample_rate);
        }
    }

    std::string bpf;
    if (args["-b"]) {
        bpf = args["-b"].asString();
    }

    std::string host_spec;
    if (args["-H"]) {
        host_spec = args["-H"].asString();
    }

    long periods = args["--periods"].asLong();

    visor::Config window_config;
    window_config.config_set<uint64_t>("num_periods", periods);
    window_config.config_set<uint64_t>("deep_sample_rate", sample_rate);

    auto input_type = PCAP;
    if (args["-i"]) {
        try {
            auto input = args["-i"].asString();
            std::transform(input.begin(), input.end(), input.begin(),
                [](unsigned char c) { return std::tolower(c); });
            input_type = input_map.at(input);
        } catch (const std::exception &e) {
            logger->error("Error parsing input type: {}", e.what());
            return -1;
        }
    }

    try {

        initialize_geo(args["--geo-city"], args["--geo-asn"]);
        std::unique_ptr<InputStream> new_input_stream;
        std::string input_text("pcap");
        switch (input_type) {
        case DNSTAP:
            input_text = "dnstap";
            new_input_stream = std::make_unique<input::dnstap::DnstapInputStream>(input_text);
            new_input_stream->config_set("dnstap_file", args["FILE"].asString());
            break;
        case SFLOW:
            input_text = "flow";
            new_input_stream = std::make_unique<input::flow::FlowInputStream>(input_text);
            new_input_stream->config_set("flow_type", "sflow");
            new_input_stream->config_set("pcap_file", args["FILE"].asString());
            break;
        case NETFLOW:
            input_text = "flow";
            new_input_stream = std::make_unique<input::flow::FlowInputStream>(input_text);
            new_input_stream->config_set("flow_type", "netflow");
            new_input_stream->config_set("pcap_file", args["FILE"].asString());
            break;
        case PCAP:
        default:
            new_input_stream = std::make_unique<input::pcap::PcapInputStream>(input_text);
            new_input_stream->config_set("pcap_file", args["FILE"].asString());
            new_input_stream->config_set("bpf", bpf);
            new_input_stream->config_set("host_spec", host_spec);
            static_cast<input::pcap::PcapInputStream *>(new_input_stream.get())->parse_host_spec();
            break;
        }

        json j;
        new_input_stream->info_json(j["info"]);
        logger->info("{}", j.dump(4));

        registry.input_manager()->module_add(std::move(new_input_stream));
        auto [input_stream_, stream_mgr_lock] = registry.input_manager()->module_get_locked(input_text);
        stream_mgr_lock.unlock();
        auto input_stream = input_stream_;
        visor::Config filter;
        auto input_proxy = input_stream->add_event_proxy(filter);

        shutdown_handler = [&]([[maybe_unused]] int signal) {
            input_stream->stop();
            logger->flush();
        };

        handler::net::NetStreamHandler *net_handler{nullptr};
        {
            auto handler_module = std::make_unique<handler::net::NetStreamHandler>("net", input_proxy, &window_config);
            handler_module->config_set("recorded_stream", true);
            handler_module->start();
            registry.handler_manager()->module_add(std::move(handler_module));
            auto [handler, handler_mgr_lock] = registry.handler_manager()->module_get_locked("net");
            handler_mgr_lock.unlock();
            net_handler = dynamic_cast<handler::net::NetStreamHandler *>(handler);
        }

        handler::dns::DnsStreamHandler *dns_handler{nullptr};
        if (input_type == PCAP || input_type == DNSTAP) {
            auto handler_module = std::make_unique<handler::dns::DnsStreamHandler>("dns", input_proxy, &window_config);
            handler_module->config_set("recorded_stream", true);
            handler_module->start();
            registry.handler_manager()->module_add(std::move(handler_module));
            auto [handler, handler_mgr_lock] = registry.handler_manager()->module_get_locked("dns");
            handler_mgr_lock.unlock();
            dns_handler = dynamic_cast<handler::dns::DnsStreamHandler *>(handler);
        }

        handler::dhcp::DhcpStreamHandler *dhcp_handler{nullptr};
        if (input_type == PCAP) {
            auto handler_module = std::make_unique<handler::dhcp::DhcpStreamHandler>("dhcp", input_proxy, &window_config);
            handler_module->config_set("recorded_stream", true);
            handler_module->start();
            registry.handler_manager()->module_add(std::move(handler_module));
            auto [handler, handler_mgr_lock] = registry.handler_manager()->module_get_locked("dhcp");
            handler_mgr_lock.unlock();
            dhcp_handler = dynamic_cast<handler::dhcp::DhcpStreamHandler *>(handler);
        }

        // blocking
        input_stream->start();

        json result;
        if (periods == 1) {
            // in summary mode we output a single summary of stats
            net_handler->window_json(result["1m"], 0, false);
            if (dns_handler) {
                dns_handler->window_json(result["1m"], 0, false);
            }
            if (dhcp_handler) {
                dhcp_handler->window_json(result["1m"], 0, false);
            }
        } else {
            // otherwise, merge the max time window available
            auto key = fmt::format("{}m", periods);
            net_handler->window_json(result[key], periods, true);
            if (dns_handler) {
                dns_handler->window_json(result[key], periods, true);
            }
            if (dhcp_handler) {
                dhcp_handler->window_json(result[key], periods, true);
            }
        }
        std::cout << result.dump() << std::endl;

        shutdown_handler(SIGINT);

    } catch (const std::exception &e) {
        logger->error("Fatal error: {}", e.what());
        result = -1;
    }

    return result;
}
