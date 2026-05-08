/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include <csignal>
#include <functional>

#include "CoreServer.h"
#include "CrashpadHandler.h"
#include "HandlerManager.h"
#include "InputStreamManager.h"
#include "Policies.h"
#include "handlers/static_plugins.h"
#include "inputs/static_plugins.h"
#include "visor_config.h"
#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wattributes"
#endif
#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif
#include <docopt/docopt.h>
#include <spdlog/sinks/basic_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#if __has_include(<unistd.h>)
#include <spdlog/sinks/syslog_sink.h>
#endif
#if __has_include(<resolv.h>)
#include <resolv.h>
#endif
#include <spdlog/spdlog.h>
#include <yaml-cpp/yaml.h>

#include "GeoDB.h"
#include "IpPort.h"
#include "timer.hpp"

static const char USAGE[] =
    R"(pktvisord.
    Usage:
      pktvisord [options] [IFACE]
      pktvisord (-h | --help)
      pktvisord --version

    pktvisord summarizes data streams and exposes a REST API control plane for configuration and metrics.

    pktvisord operation is configured via Taps and Collection Policies. Taps abstract the process of "tapping into"
    input streams with templated configuration while Policies use Taps to instantiate and configure Input and Stream
    Handlers to analyze and summarize stream data, which is then made available for collection via REST API.

    Taps and Collection Policies may be created by passing the appropriate YAML configuration file to
    --config, and/or by enabling the admin REST API with --admin-api and using the appropriate endpoints.

    Alternatively, for simple use cases you may specify IFACE, which is either a network interface, an
    IP address (4 or 6), or "auto". If this is specified, "default" Tap and Collection Policies will be created with
    a "pcap" input stream on the specified interfaced, along with the built in "net", "dns", and "pcap"
    Stream Handler modules attached. If "auto" is specified, the most used ethernet interface will be chosen.
    Note that this feature may be deprecated in the future.

    For more documentation, see https://pktvisor.dev

    Base Options:
      -d                                    Daemonize; fork and continue running in the background [default: false]
      -h --help                             Show this screen
      -v                                    Verbose log output
      --no-track                            Don't send lightweight, anonymous usage metrics
      --version                             Show version
    Web Server Options:
      -l HOST                               Run web server on the given host or IP (default: localhost)
      -p PORT                               Run web server on the given port (default: 10853)
      --tls                                 Enable TLS on the web server
      --tls-cert FILE                       Use given TLS cert. Required if --tls is enabled.
      --tls-key FILE                        Use given TLS private key. Required if --tls is enabled.
      --admin-api                           Enable admin REST API giving complete control plane functionality [default: false]
                                            When not specified, the exposed API is read-only access to module status and metrics.
                                            When specified, write access is enabled for all modules.
    Geo Options:
      --geo-city FILE                       GeoLite2 City database to use for IP to Geo mapping
      --geo-asn FILE                        GeoLite2 ASN database to use for IP to ASN mapping
      --geo-cache-size N                    GeoLite2 LRU cache size, 0 to disable. (default: 10000)
      --default-geo-city FILE               Default GeoLite2 City database to be loaded if no other is specified
      --default-geo-asn FILE                Default GeoLite2 ASN database to be loaded if no other is specified
    Configuration:
      --config FILE                         Use specified YAML configuration to configure options, Taps, and Collection Policies
                                            Please see https://pktvisor.dev for more information
    Crashpad:
      --cp-disable                          Disable crashpad collector
      --cp-token TOKEN                      Crashpad token for remote crash reporting
      --cp-url URL                          Crashpad server url
      --cp-custom USERDEF                   Crashpad optional user defined field
      --cp-path PATH                        Crashpad handler binary
    Modules:
      --module-list                         List all modules which have been loaded (builtin and dynamic).
      --module-dir DIR                      Set module load path. All modules in this directory will be loaded.
    Logging Options:
      --log-file FILE                       Log to the given output file name
      --syslog                              Log to syslog
    Prometheus Options:
      --prometheus                          Ignored, Prometheus output always enabled (left for backwards compatibility)
      --prom-instance ID                    Optionally set the 'instance' label to given ID
    OpenTelemetry Options
      --otel                                Enable OpenTelemetry OTLP exporter over HTTP(S)
      --otel-host HOST                      Set OTEL destination IP where the data will be pushed to (default: localhost)
      --otel-path PATH                      Set OTEL destination URL path (default: /v1/metrics)
      --otel-port PORT                      Set OTEL destination port number (default: 4318)
      --otel-interval N                     The interval in seconds that exporter will periodically push data (default: 60)
      --otel-tls                            Enable TLS when connecting to OTEL destination
      --otel-tls-cert FILE                  Use given TLS cert. Required if --otel-tls is enabled.
      --otel-tls-key FILE                   Use given TLS private key. Required if --otel-tls is enabled.
    Metric Enrichment Options:
      --iana-service-port-registry FILE     IANA Service Name and Transport Protocol Port Number Registry file in CSV format
      --default-service-registry FILE       Default IANA Service Name Port Number Registry CSV file to be loaded if no other is specified
    Handler Module Defaults:
      --max-deep-sample N                   Never deep sample more than N% of streams (an int between 0 and 100) (default: 100)
      --periods P                            Hold this many 60 second time periods of history in memory (default: 5)
    pcap Input Module Options:              (applicable to default policy when IFACE is specified only)
      -b BPF                                Filter packets using the given tcpdump compatible filter expression. Example: "port 53"
      -H HOSTSPEC                           Specify subnets (comma separated) to consider HOST, in CIDR form. In live capture this
                                            /may/ be detected automatically from capture device but /must/ be specified for pcaps.
                                            Example: "10.0.1.0/24,10.0.2.1/32,2001:db8::/64"
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

struct CmdOptions {
    bool daemon{false};
    bool syslog{false};
    bool verbose{false};
    bool no_track{false};
    bool prometheus{false};
    std::optional<std::string> log_file;
    std::optional<std::string> prom_instance;
    std::optional<std::string> geo_city;
    std::optional<std::string> geo_asn;
    std::optional<unsigned int> geo_cache_size;
    std::optional<unsigned int> max_deep_sample;
    std::optional<unsigned int> periods;
    std::optional<YAML::Node> config;

    struct WebServer {
        bool tls_support{false};
        bool admin_api{false};
        std::optional<unsigned int> port;
        std::optional<std::string> host;
        std::optional<std::string> tls_cert;
        std::optional<std::string> tls_key;
    };
    WebServer web_server;

    struct Opentelemetry {
        bool otel_support{false};
        bool tls_support{false};
        std::optional<unsigned int> interval;
        std::optional<unsigned int> port;
        std::optional<std::string> host;
        std::optional<std::string> path;
        std::optional<std::string> tls_cert;
        std::optional<std::string> tls_key;
    };
    Opentelemetry otel_setup;

    struct Crashpad {
        bool disable{false};
        std::optional<std::string> token;
        std::optional<std::string> url;
        std::optional<std::string> user_defined;
        std::optional<base::FilePath::StringType> path;
    };
    Crashpad crashpad_info;

    std::optional<std::string> iana_ports_path;

    struct Module {
        bool list{false};
        std::optional<std::string> dir;
    };
    Module module;
};

void fill_cmd_options(std::map<std::string, docopt::value> args, CmdOptions &options)
{
    YAML::Node config;
    auto logger = spdlog::stdout_color_mt("visor");
    // local config file
    if (args["--config"]) {
        YAML::Node config_file;
        // look for local options
        try {
            config_file = YAML::LoadFile(args["--config"].asString());

            if (!config_file.IsMap() || !config_file["visor"]) {
                logger->error("invalid schema in config file: {}", args["--config"].asString());
                exit(EXIT_FAILURE);
            }
            if (!config_file["version"]) {
                logger->info("missing version in config file, using version \"1.0\"");
            } else if (!config_file["version"].IsScalar() || config_file["version"].as<std::string>() != "1.0") {
                logger->error("unsupported version in config file: {}", args["--config"].asString());
                exit(EXIT_FAILURE);
            }

            options.config = config_file;

            if (config_file["visor"]["config"] && config_file["visor"]["config"].IsMap()) {
                config = config_file["visor"]["config"];
            }
        } catch (std::runtime_error &e) {
            logger->error("{} in config file: {}", e.what(), args["--config"].asString());
            exit(EXIT_FAILURE);
        }
    }

    spdlog::drop("visor");

    options.verbose = (config["verbose"] && config["verbose"].as<bool>()) || args["-v"].asBool();
    options.daemon = (config["daemon"] && config["daemon"].as<bool>()) || args["-d"].asBool();
    options.syslog = (config["syslog"] && config["syslog"].as<bool>()) || args["--syslog"].asBool();
    options.no_track = (config["no_track"] && config["no_track"].as<bool>()) || args["--no-track"].asBool();
    options.prometheus = (config["prometheus"] && config["prometheus"].as<bool>()) || args["--prometheus"].asBool();

    if (args["--log-file"]) {
        options.log_file = args["--log-file"].asString();
    } else if (config["log_file"]) {
        options.log_file = config["log_file"].as<std::string>();
    }

    if (args["--prom-instance"]) {
        options.prom_instance = args["--prom-instance"].asString();
    } else if (config["prom_instance"]) {
        options.prom_instance = config["prom_instance"].as<std::string>();
    }

    if (args["--geo-city"]) {
        options.geo_city = args["--geo-city"].asString();
    } else if (config["geo_city"]) {
        options.geo_city = config["geo_city"].as<std::string>();
    } else if (args["--default-geo-city"]) {
        options.geo_city = args["--default-geo-city"].asString();
    } else if (config["default_geo_city"]) {
        options.geo_city = config["default_geo_city"].as<std::string>();
    } else {
        options.geo_city = "";
    }

    if (args["--geo-asn"]) {
        options.geo_asn = args["--geo-asn"].asString();
    } else if (config["geo_asn"]) {
        options.geo_asn = config["geo_asn"].as<std::string>();
    } else if (args["--default-geo-asn"]) {
        options.geo_asn = args["--default-geo-asn"].asString();
    } else if (config["default_geo_asn"]) {
        options.geo_asn = config["default_geo_asn"].as<std::string>();
    } else {
        options.geo_asn = "";
    }

    if (args["--geo-cache-size"]) {
        options.geo_cache_size = static_cast<unsigned int>(args["--geo-cache-size"].asLong());
    } else if (config["geo_cache_size"]) {
        options.geo_cache_size = config["geo_cache_size"].as<unsigned int>();
    } else {
        options.geo_cache_size = 10000;
    }

    if (args["--max-deep-sample"]) {
        options.max_deep_sample = static_cast<unsigned int>(args["--max-deep-sample"].asLong());
    } else if (config["max_deep_sample"]) {
        options.max_deep_sample = config["max_deep_sample"].as<unsigned int>();
    } else {
        options.max_deep_sample = 100;
    }

    if (args["--periods"]) {
        options.periods = static_cast<unsigned int>(args["--periods"].asLong());
    } else if (config["periods"]) {
        options.periods = config["periods"].as<unsigned int>();
    } else {
        options.periods = 5;
    }

    options.web_server.tls_support = (config["tls"] && config["tls"].as<bool>()) || args["--tls"].asBool();
    options.web_server.admin_api = (config["admin_api"] && config["admin_api"].as<bool>()) || args["--admin-api"].asBool();

    if (args["-p"]) {
        options.web_server.port = static_cast<unsigned int>(args["-p"].asLong());
    } else if (config["port"]) {
        options.web_server.port = config["port"].as<unsigned int>();
    } else {
        options.web_server.port = 10853;
    }

    if (args["-l"]) {
        options.web_server.host = args["-l"].asString();
    } else if (config["host"]) {
        options.web_server.host = config["host"].as<std::string>();
    } else {
        options.web_server.host = "localhost";
    }

    if (args["--tls-cert"]) {
        options.web_server.tls_cert = args["--tls-cert"].asString();
    } else if (config["tls_cert"]) {
        options.web_server.tls_cert = config["tls_cert"].as<std::string>();
    }

    if (args["--tls-key"]) {
        options.web_server.tls_key = args["--tls-key"].asString();
    } else if (config["tls_key"]) {
        options.web_server.tls_key = config["tls_key"].as<std::string>();
    }

    options.otel_setup.otel_support = (config["otel"] && config["otel"].as<bool>()) || args["--otel"].asBool();
    options.otel_setup.tls_support = (config["otel_tls"] && config["otel_tls"].as<bool>()) || args["--otel-tls"].asBool();

    if (args["--otel-host"]) {
        options.otel_setup.host = args["--otel-host"].asString();
    } else if (config["otel_host"]) {
        options.otel_setup.host = config["otel_host"].as<std::string>();
    } else {
        options.otel_setup.host = "localhost";
    }

    if (args["--otel-path"]) {
        options.otel_setup.path = args["--otel-path"].asString();
    } else if (config["otel_host"]) {
        options.otel_setup.path = config["otel_path"].as<std::string>();
    } else {
        options.otel_setup.path = "/v1/metrics";
    }

    if (args["--otel-port"]) {
        options.otel_setup.port = static_cast<unsigned int>(args["--otel-port"].asLong());
    } else if (config["otel_port"]) {
        options.otel_setup.port = config["otel_port"].as<unsigned int>();
    } else {
        options.otel_setup.port = 4318;
    }

    if (args["--otel-interval"]) {
        options.otel_setup.interval = static_cast<unsigned int>(args["--otel-interval"].asLong());
    } else if (config["otel_interval"]) {
        options.otel_setup.interval = config["otel_interval"].as<unsigned int>();
    } else {
        options.otel_setup.interval = 60;
    }

    if (args["--otel-tls-cert"]) {
        options.otel_setup.tls_cert = args["--otel-tls-cert"].asString();
    } else if (config["otel_tls_cert"]) {
        options.otel_setup.tls_cert = config["otel_tls_cert"].as<std::string>();
    }

    if (args["--otel-tls-key"]) {
        options.otel_setup.tls_key = args["--otel-tls-key"].asString();
    } else if (config["otel_tls_key"]) {
        options.otel_setup.tls_key = config["otel_tls_key"].as<std::string>();
    }

    options.module.list = (config["module_list"] && config["module_list"].as<bool>()) || args["--module-list"].asBool();

    if (args["--module-dir"]) {
        options.module.dir = args["--module-dir"].asString();
    } else if (config["module_dir"]) {
        options.module.dir = config["module_dir"].as<std::string>();
    }

    if (args["--iana-service-port-registry"]) {
        options.iana_ports_path = args["--iana-service-port-registry"].asString();
    } else if (config["iana_service_port_registry"]) {
        options.iana_ports_path = config["iana_service_port_registry"].as<std::string>();
    } else if (args["--default-service-registry"]) {
        options.iana_ports_path = args["--default-service-registry"].asString();
    } else if (config["default_service_registry"]) {
        options.iana_ports_path = config["default_service_registry"].as<std::string>();
    }

    options.crashpad_info.disable = (config["cp_disable"] && config["cp_disable"].as<bool>()) || args["--cp-disable"].asBool();

    if (args["--cp-token"]) {
        options.crashpad_info.token = args["--cp-token"].asString();
    } else if (config["cp_token"]) {
        options.crashpad_info.token = config["cp_token"].as<std::string>();
    }

    if (args["--cp-url"]) {
        options.crashpad_info.url = args["--cp-url"].asString();
    } else if (config["cp_url"]) {
        options.crashpad_info.url = config["cp_url"].as<std::string>();
    }

    if (args["--cp-custom"]) {
        options.crashpad_info.user_defined = args["--cp-custom"].asString();
    } else if (config["cp_custom"]) {
        options.crashpad_info.user_defined = config["cp_custom"].as<std::string>();
    } else {
        options.crashpad_info.user_defined = std::string();
    }

    if (args["--cp-path"]) {
        auto v = args["--cp-path"].asString();
        base::FilePath::StringType cp(v.begin(), v.end());
        options.crashpad_info.path = cp;
    } else if (config["cp_path"]) {
        auto v = config["cp_path"].as<std::string>();
        base::FilePath::StringType cp(v.begin(), v.end());
        options.crashpad_info.path = cp;
    }
}

void initialize_geo(const std::string &city, const std::string &asn, unsigned int cache_size)
{
    if (!city.empty()) {
        geo::GeoIP().enable(city, cache_size);
    }
    if (!asn.empty()) {
        geo::GeoASN().enable(asn, cache_size);
    }
}

// adapted from LPI becomeDaemon() only for UNIX
#if __has_include(<unistd.h>)
int daemonize()
{

    switch (auto pid = fork()) {
    case -1:
        return -1;
    case 0:
        // Child falls through...
        break;
    default:
        // while parent terminates
        spdlog::get("pktvisor-daemon")->info("daemonized to PID {}", pid);
        _exit(EXIT_SUCCESS);
    }

    // Become leader of new session
    if (setsid() == -1) {
        spdlog::get("pktvisor-daemon")->error("setsid() fail");
        return -1;
    }

    // Clear file mode creation mask
    umask(0);

    // Reopen standard fd's to /dev/null
    close(STDIN_FILENO);

    int fd = open("/dev/null", O_RDWR);

    if (fd != STDIN_FILENO) {
        spdlog::get("pktvisor-daemon")->error("open() fail");
        return -1;
    }
    if (dup2(STDIN_FILENO, STDOUT_FILENO) != STDOUT_FILENO) {
        spdlog::get("pktvisor-daemon")->error("dup2 fail (STDOUT)");
        return -1;
    }
    if (dup2(STDIN_FILENO, STDERR_FILENO) != STDERR_FILENO) {
        spdlog::get("pktvisor-daemon")->error("dup2 fail (STDERR)");
        return -1;
    }

    return 0;
}
#else
int daemonize()
{
    return 0;
}
#endif

auto default_tap_policy = R"(
version: "1.0"

visor:
  taps:
    default:
      input_type: pcap
      config:
        iface: "{}"
        host_spec: "{}"
  policies:
    default:
      kind: collection
      input:
        tap: default
        input_type: pcap
        config:
          bpf: "{}"
      handlers:
        window_config:
          num_periods: {}
          deep_sample_rate: {}
        modules:
          net:
            type: net
          dhcp:
            type: dhcp
          dns:
            type: dns
          pcap_stats:
            type: pcap
)";

int main(int argc, char *argv[])
{
    std::map<std::string, docopt::value> args = docopt::docopt(USAGE,
        {argv + 1, argv + argc},
        true,           // show help if requested
        VISOR_VERSION); // version string

    CmdOptions options;
    fill_cmd_options(args, options);

    if (options.daemon) {
        // before we daemonize, if they are using a log file, ensure it can be opened
        if (options.log_file.has_value()) {
            try {
                auto logger_probe = spdlog::basic_logger_mt("pktvisor-log-probe", options.log_file.value());
            } catch (const spdlog::spdlog_ex &ex) {
                std::cerr << "Log init failed: " << ex.what() << std::endl;
                exit(EXIT_FAILURE);
            }
        }
        auto dlogger = spdlog::stderr_color_st("pktvisor-daemon");
        dlogger->flush_on(spdlog::level::info);
        if (daemonize()) {
            dlogger->error("failed to daemonize");
            exit(EXIT_FAILURE);
        }
    }

    std::shared_ptr<spdlog::logger> logger;
    spdlog::flush_on(spdlog::level::err);
    if (options.log_file.has_value()) {
        try {
            logger = spdlog::basic_logger_mt("visor", options.log_file.value());
            spdlog::flush_every(std::chrono::seconds(3));
        } catch (const spdlog::spdlog_ex &ex) {
            std::cerr << "Log init failed: " << ex.what() << std::endl;
            exit(EXIT_FAILURE);
        }
    } else if (options.syslog) {
#if __has_include(<unistd.h>)
        logger = spdlog::syslog_logger_mt("visor", "pktvisord", LOG_PID, LOG_DAEMON);
#endif
    } else {
        logger = spdlog::stdout_color_mt("visor");
    }
    if (options.verbose) {
        logger->set_level(spdlog::level::debug);
    }

    // crashpad support
    if (!options.crashpad_info.disable) {
        if (options.crashpad_info.token.has_value() || options.crashpad_info.url.has_value() || options.crashpad_info.path.has_value()) {
            if (options.crashpad_info.token.has_value() && options.crashpad_info.url.has_value() && options.crashpad_info.path.has_value()) {
                if (!crashpad::start_crashpad_handler(options.crashpad_info.token.value(), options.crashpad_info.url.value(), options.crashpad_info.user_defined.value(), options.crashpad_info.path.value())) {
                    logger->error("failed to setup crashpad");
                }
            } else {
                logger->error("missing information to setup crashpad");
                exit(EXIT_FAILURE);
            }
        }
    }

    // modules
    CoreRegistry registry;
    if (options.module.dir.has_value()) {
        logger->warn("--module-dir is no longer supported (plugins are now statically linked); ignoring '{}'", options.module.dir.value());
    }

    // window config defaults for all policies
    registry.handler_manager()->set_default_deep_sample_rate(options.max_deep_sample.value());
    registry.handler_manager()->set_default_num_periods(options.periods.value());

    logger->info("{} starting up", VISOR_VERSION);

    // if we are demonized, change to root directory now that (potentially) logs are open
    if (options.daemon) {
#if __has_include(<unistd.h>)
        [[maybe_unused]] int result = chdir("/");
#endif
    }

    PrometheusConfig prom_config;
    prom_config.default_path = "/metrics";
    if (options.prom_instance.has_value()) {
        prom_config.instance_label = options.prom_instance.value();
    }

    HttpConfig http_config;
    http_config.read_only = !options.web_server.admin_api;
    if (options.web_server.tls_support) {
        http_config.tls_enabled = true;
        if (!options.web_server.tls_key.has_value() || !options.web_server.tls_cert.has_value()) {
            logger->error("you must specify --tls-key and --tls-cert to use --tls");
            exit(EXIT_FAILURE);
        }
        http_config.key = options.web_server.tls_key.value();
        http_config.cert = options.web_server.tls_cert.value();
        logger->info("Enabling TLS with cert {} and key {}", http_config.key, http_config.cert);
    }

    OtelConfig otel_config;
    if (options.otel_setup.otel_support) {
        otel_config.enable = true;
        if (options.otel_setup.tls_support) {
            if (!options.otel_setup.tls_key.has_value() || !options.otel_setup.tls_cert.has_value()) {
                logger->error("you must specify --otel-tls-key and --otel-tls-cert to use --otel-tls");
                exit(EXIT_FAILURE);
            }
            otel_config.tls_key = options.otel_setup.tls_key.value();
            otel_config.tls_cert = options.otel_setup.tls_cert.value();
            logger->info("Enabling OTEL TLS with cert {} and key {}", otel_config.tls_key, otel_config.tls_cert);
        }
        otel_config.path = options.otel_setup.path.value();
        otel_config.endpoint = options.otel_setup.host.value();
        otel_config.port_number = options.otel_setup.port.value();
    }

    std::unique_ptr<CoreServer> svr;
    try {
        svr = std::make_unique<CoreServer>(&registry, logger, http_config, otel_config, prom_config);
    } catch (const std::exception &e) {
        logger->error(e.what());
        logger->info("exit with failure");
        exit(EXIT_FAILURE);
    }
    svr->set_http_logger([&logger](const auto &req, const auto &res) {
        logger->info("REQUEST: {} {} {}", req.method, req.path, res.status);
        if (res.status == 500) {
            logger->error(res.body);
        }
    });

    if (options.module.list) {
        for (const auto &entry : visor::InputPluginRegistry::instance().entries()) {
            logger->info("input: {} version {}", entry.alias, entry.version);
        }
        for (const auto &entry : visor::HandlerPluginRegistry::instance().entries()) {
            logger->info("handler: {} version {}", entry.alias, entry.version);
        }
        exit(EXIT_SUCCESS);
    }

    if (options.iana_ports_path.has_value()) {
        try {
            visor::network::IpPort::set_csv_iana_ports(options.iana_ports_path.value());
        } catch (const std::exception &e) {
            logger->error(e.what());
            logger->info("exit with failure");
            exit(EXIT_FAILURE);
        }
    }

    // local config file
    if (options.config.has_value()) {
        // pass to CoreManagers
        try {
            svr->registry()->configure_from_yaml(options.config.value());
        } catch (const std::exception &e) {
            logger->error(e.what());
            logger->info("exit with failure");
            exit(EXIT_FAILURE);
        }
    }

    shutdown_handler = [&]([[maybe_unused]] int signal) {
        logger->info("Shutting down");
        logger->flush();
        svr->stop();
        logger->flush();
    };
    std::signal(SIGINT, signal_handler);
    std::signal(SIGTERM, signal_handler);

    auto host = options.web_server.host.value();
    auto port = options.web_server.port.value();

    unsigned int sample_rate = 100;
    if (options.max_deep_sample.has_value()) {
        sample_rate = options.max_deep_sample.value();
        if (sample_rate != 100) {
            logger->info("Using maximum deep sample rate: {}%", sample_rate);
        }
    }

    /**
     * anonymous lightweight usage metrics, to help understand project usage
     */
#if __has_include(<resolv.h>)
    std::shared_ptr<timer::interval_handle> timer_handle;
    auto usage_metrics = [&logger] {
        u_char buf[1024];
        std::string version_str{VISOR_VERSION_NUM};
        std::reverse(version_str.begin(), version_str.end());
        std::string target = version_str + ".pktvisord.metrics.pktvisor.dev.";
        logger->info("sending anonymous usage metrics (once/day, use --no-track to disable): {}", target);
        if (res_query(target.c_str(), ns_c_in, ns_t_txt, buf, 1024) < 0) {
            logger->warn("metrics send failed");
        }
    };
    if (!options.no_track) {
        static timer timer_thread{1min};
        // once at start up
        usage_metrics();
        // once per day
        timer_handle = timer_thread.set_interval(24h, usage_metrics);
    }
#endif

    unsigned int periods = options.periods.value();

    try {
        initialize_geo(options.geo_city.value(), options.geo_asn.value(), options.geo_cache_size.value());
    } catch (const std::exception &e) {
        logger->error("Fatal error: {}", e.what());
        exit(EXIT_FAILURE);
    }

    if (args["IFACE"]) {
        // pcap command line functionality, create default policy
        try {
            std::string bpf;
            if (args["-b"]) {
                bpf = args["-b"].asString();
            }

            std::string host_spec;
            if (args["-H"]) {
                host_spec = args["-H"].asString();
            }

            auto policy_str = fmt::format(default_tap_policy, args["IFACE"].asString(), host_spec, bpf, periods, sample_rate);
            logger->debug(policy_str);
            svr->registry()->configure_from_str(policy_str);

        } catch (const std::exception &e) {
            logger->error(e.what());
            logger->info("exit with failure");
            exit(EXIT_FAILURE);
        }
    } else if (!options.web_server.admin_api) {
        // if they didn't specify pcap target, or config file, or admin api then there is nothing to do
        logger->error("Nothing to do: specify --admin-api or IFACE.");
        std::cerr << USAGE << std::endl;
        exit(EXIT_FAILURE);
    }

    try {
        svr->start(host.c_str(), port);
    } catch (const std::exception &e) {
        logger->error(e.what());
        logger->info("exit with failure");
        exit(EXIT_FAILURE);
    }

    logger->info("exit with success");
    return EXIT_SUCCESS;
}
