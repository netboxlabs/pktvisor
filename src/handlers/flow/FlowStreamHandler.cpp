/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "FlowStreamHandler.h"
#include "HandlerModulePlugin.h"
#include "Tos.h"
#include <Corrade/Utility/Debug.h>
#include <fmt/format.h>
#ifdef _WIN32
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif

namespace visor::handler::flow {

static std::string ip_summarization(const pcpp::IPAddress &ip, SummaryData *summary)
{
    if (summary && summary->type != IpSummary::None) {
        if (ip.isIPv4() && match_subnet(summary->ipv4_exclude_summary, ip.getIPv4().toInt()).has_value()) {
            return ip.toString();
        } else if (ip.isIPv6() && match_subnet(summary->ipv6_exclude_summary, ip.getIPv6().toBytes()).has_value()) {
            return ip.toString();
        }
        bool check_subnet{false};
        if (summary->type == IpSummary::ByASN && HandlerModulePlugin::asn->enabled()) {
            std::string asn;
            if (ip.isIPv4()) {
                sockaddr_in sa4{};
                if (lib::utils::ipv4_to_sockaddr(ip.getIPv4(), &sa4)) {
                    asn = HandlerModulePlugin::asn->getASNString(&sa4);
                }
            } else if (ip.isIPv6()) {
                sockaddr_in6 sa6{};
                if (lib::utils::ipv6_to_sockaddr(ip.getIPv6(), &sa6)) {
                    asn = HandlerModulePlugin::asn->getASNString(&sa6);
                }
            }
            if (summary->exclude_unknown_asns && asn == "Unknown") {
                check_subnet = true;
            } else if (!summary->asn_exclude_summary.empty() && std::any_of(summary->asn_exclude_summary.begin(), summary->asn_exclude_summary.end(), [&asn](const auto &prefix) {
                           return asn.size() >= prefix.size() && 0 == asn.compare(0, prefix.size(), prefix);
                       })) {
                check_subnet = true;
            }
            if (!check_subnet) {
                return asn;
            }
        }
        if (summary->type == IpSummary::BySubnet || check_subnet) {
            if (ip.isIPv4()) {
                if (auto subnet = match_subnet(summary->ipv4_summary, ip.getIPv4().toInt()); subnet.has_value()) {
                    return subnet.value()->str;
                } else if (summary->ipv4_wildcard.has_value()) {
                    auto cidr = summary->ipv4_wildcard.value().cidr;
                    return pcpp::IPv4Address(lib::utils::get_subnet(ip.getIPv4().toInt(), cidr)).toString() + "/" + std::to_string(cidr);
                }
            } else if (ip.isIPv6()) {
                if (auto subnet = match_subnet(summary->ipv6_summary, ip.getIPv6().toBytes()); subnet.has_value()) {
                    return subnet.value()->str;
                } else if (summary->ipv6_wildcard.has_value()) {
                    auto cidr = summary->ipv6_wildcard.value().cidr;
                    return pcpp::IPv6Address(lib::utils::get_subnet(ip.getIPv6().toBytes(), cidr).data()).toString() + "/" + std::to_string(cidr);
                }
            }
        }
    }
    return ip.toString();
}

FlowStreamHandler::FlowStreamHandler(const std::string &name, InputEventProxy *proxy, const Configurable *window_config)
    : visor::StreamMetricsHandler<FlowMetricsManager>(name, window_config)
    , _sample_rate_scaling(true)
{
    // figure out which input event proxy we have
    if (proxy) {
        _mock_proxy = dynamic_cast<MockInputEventProxy *>(proxy);
        _flow_proxy = dynamic_cast<FlowInputEventProxy *>(proxy);
        if (!_mock_proxy && !_flow_proxy) {
            throw StreamHandlerException(fmt::format("FlowStreamHandler: unsupported input event proxy {}", proxy->name()));
        }
    }
}

void FlowStreamHandler::start()
{
    if (_running) {
        return;
    }

    validate_configs(_config_defs);

    // default enabled groups
    _groups.set(group::FlowMetrics::Counters);
    _groups.set(group::FlowMetrics::Cardinality);
    _groups.set(group::FlowMetrics::TopIPs);
    _groups.set(group::FlowMetrics::TopPorts);
    _groups.set(group::FlowMetrics::TopIPPorts);
    _groups.set(group::FlowMetrics::ByBytes);
    _groups.set(group::FlowMetrics::ByPackets);

    process_groups(_group_defs);

    // Setup Configs
    if (config_exists("recorded_stream")) {
        _metrics->set_recorded_stream();
    }

    EnrichData enrich_data;
    if (config_exists("device_map")) {
        auto devices = config_get<std::shared_ptr<Configurable>>("device_map");
        for (const auto &device : devices->get_all_keys()) {
            if (!pcpp::IPv4Address(device).isValid() && !pcpp::IPv6Address(device).isValid()) {
                throw StreamHandlerException(fmt::format("FlowHandler: 'device_map' config has an invalid device IP: {}", device));
            }
            DeviceEnrich enrich_device;
            auto device_map = devices->config_get<std::shared_ptr<Configurable>>(device);
            if (!device_map->config_exists("name")) {
                throw StreamHandlerException(fmt::format("FlowHandler: 'device_map' config with device IP {} does not have 'name' key", device));
            }
            enrich_device.name = device_map->config_get<std::string>("name");
            if (device_map->config_exists("description")) {
                enrich_device.descr = device_map->config_get<std::string>("description");
            }
            if (!device_map->config_exists("interfaces")) {
                throw StreamHandlerException(fmt::format("FlowHandler: 'device_map' config with device IP {} does not have 'interfaces' key", device));
            }
            auto interfaces = device_map->config_get<std::shared_ptr<Configurable>>("interfaces");
            for (auto const &interface : interfaces->get_all_keys()) {
                auto if_index = static_cast<uint32_t>(std::stol(interface));
                auto interface_map = interfaces->config_get<std::shared_ptr<Configurable>>(interface);
                if (!interface_map->config_exists("name")) {
                    throw StreamHandlerException(fmt::format("FlowHandler: 'device_map' config with device IP {} does not have 'name' key", device));
                }
                if (interface_map->config_exists("description")) {
                    enrich_device.interfaces[if_index] = {interface_map->config_get<std::string>("name"), interface_map->config_get<std::string>("description")};
                } else {
                    enrich_device.interfaces[if_index] = {interface_map->config_get<std::string>("name"), std::string()};
                }
            }
            enrich_data[device] = enrich_device;
        }
    }

    if (!config_exists("enrichment") || config_get<bool>("enrichment")) {
        _metrics->set_enrich_data(std::move(enrich_data));
    }

    SummaryData summary_data;
    if (config_exists("exclude_ips_from_summarization")) {
        parse_host_specs(config_get<StringList>("exclude_ips_from_summarization"), summary_data.ipv4_exclude_summary, summary_data.ipv6_exclude_summary);
    }
    if (config_exists("summarize_ips_by_asn") && config_get<bool>("summarize_ips_by_asn")) {
        summary_data.type = IpSummary::ByASN;
        if (config_exists("exclude_asns_from_summarization")) {
            for (const auto &asn : config_get<StringList>("exclude_asns_from_summarization")) {
                summary_data.asn_exclude_summary.push_back(asn + "/");
            }
        }
        if (config_exists("exclude_unknown_asns_from_summarization")) {
            summary_data.exclude_unknown_asns = config_get<bool>("exclude_unknown_asns_from_summarization");
        }
    }
    if (config_exists("subnets_for_summarization")) {
        if (summary_data.type == IpSummary::None) {
            summary_data.type = IpSummary::BySubnet;
        }
        parse_host_specs(config_get<StringList>("subnets_for_summarization"), summary_data.ipv4_summary, summary_data.ipv6_summary);
        // check ipv4 wildcard
        auto it_v4_remove = summary_data.ipv4_summary.end();
        for (auto it = summary_data.ipv4_summary.begin(); it != summary_data.ipv4_summary.end(); it++) {
            if (!it->addr.s_addr) {
                if (summary_data.ipv4_wildcard.has_value()) {
                    throw StreamHandlerException("FlowHandler: 'subnets_for_summarization' only allows one ipv4 and one ipv6 wildcard");
                }
                summary_data.ipv4_wildcard = *it;
                it_v4_remove = it;
            }
        }
        if (it_v4_remove != summary_data.ipv4_summary.end()) {
            summary_data.ipv4_summary.erase(it_v4_remove);
        }
        // check ipv6 wildcard
        auto it_v6_remove = summary_data.ipv6_summary.end();
        for (auto it = summary_data.ipv6_summary.begin(); it != summary_data.ipv6_summary.end(); it++) {
            bool wildcard = true;
            for (size_t i = 0; i < sizeof(it->addr.s6_addr); ++i) {
                if (it->addr.s6_addr[i]) {
                    wildcard = false;
                    break;
                }
            }
            if (wildcard) {
                if (summary_data.ipv6_wildcard.has_value()) {
                    throw StreamHandlerException("FlowHandler: 'subnets_for_summarization' only allows one ipv4 and one ipv6 wildcard");
                }
                summary_data.ipv6_wildcard = *it;
                it_v6_remove = it;
            }
        }
        if (it_v6_remove != summary_data.ipv6_summary.end()) {
            summary_data.ipv6_summary.erase(it_v6_remove);
        }
    }

    if (summary_data.type != IpSummary::None) {
        _metrics->set_summary_data(std::move(summary_data));
    }

    // Setup Filters
    if (config_exists("only_ips")) {
        parse_host_specs(config_get<StringList>("only_ips"), _only_ipv4_list, _only_ipv6_list);
        _f_enabled.set(Filters::OnlyIps);
    }

    if (config_exists("only_device_interfaces")) {
        auto devices = config_get<std::shared_ptr<Configurable>>("only_device_interfaces");
        for (const auto &device : devices->get_all_keys()) {
            if (pcpp::IPv4Address(device).isValid()) {
                _device_interfaces_list[device] = _parse_interfaces(devices->config_get<StringList>(device));
            } else if (pcpp::IPv6Address(device).isValid()) {
                _device_interfaces_list[device] = _parse_interfaces(devices->config_get<StringList>(device));
            } else {
                throw StreamHandlerException(fmt::format("FlowHandler: 'only_device_interfaces' filter has an invalid device IP: {}", device));
            }
        }
        _f_enabled.set(Filters::OnlyDeviceInterfaces);
    }

    if (config_exists("only_ports")) {
        _parse_ports(config_get<StringList>("only_ports"));
        _f_enabled.set(Filters::OnlyPorts);
    }

    if (config_exists("only_directions")) {
        _f_enabled.set(Filters::DisableIn);
        _f_enabled.set(Filters::DisableOut);
        for (const auto &dir : config_get<StringList>("only_directions")) {
            if (dir == "in") {
                _f_enabled.reset(Filters::DisableIn);
            } else if (dir == "out") {
                _f_enabled.reset(Filters::DisableOut);
            } else {
                throw ConfigException(fmt::format("FlowStreamHandler: only_directions filter contained an invalid/unsupported direction: {}", dir));
            }
        }
    }

    if (config_exists("geoloc_notfound") && config_get<bool>("geoloc_notfound")) {
        _f_enabled.set(Filters::GeoLocNotFound);
    }

    if (config_exists("asn_notfound") && config_get<bool>("asn_notfound")) {
        _f_enabled.set(Filters::AsnNotFound);
    }

    if (config_exists("sample_rate_scaling") && !config_get<bool>("sample_rate_scaling")) {
        _sample_rate_scaling = false;
    }

    if (_flow_proxy) {
        _sflow_connection = _flow_proxy->sflow_signal.connect(&FlowStreamHandler::process_sflow_cb, this);
        _netflow_connection = _flow_proxy->netflow_signal.connect(&FlowStreamHandler::process_netflow_cb, this);
        _heartbeat_connection = _flow_proxy->heartbeat_signal.connect(&FlowStreamHandler::check_period_shift, this);
    }

    _running = true;
}

void FlowStreamHandler::stop()
{
    if (!_running) {
        return;
    }

    if (_flow_proxy) {
        _sflow_connection.disconnect();
        _netflow_connection.disconnect();
        _heartbeat_connection.disconnect();
    }

    _running = false;
}

FlowStreamHandler::~FlowStreamHandler()
{
}

// callback from input module
void FlowStreamHandler::set_start_tstamp(timespec stamp)
{
    _metrics->set_start_tstamp(stamp);
}

void FlowStreamHandler::set_end_tstamp(timespec stamp)
{
    _metrics->set_end_tstamp(stamp);
}

void FlowStreamHandler::process_sflow_cb(const SFSample &payload, [[maybe_unused]] size_t rawSize)
{
    timespec stamp{};
    // use now()
    std::timespec_get(&stamp, TIME_UTC);

    std::string agentId;
    if (payload.agent_addr.type == SFLADDRESSTYPE_IP_V4) {
        agentId = pcpp::IPv4Address(payload.agent_addr.address.ip_v4.addr).toString();
    } else if (payload.agent_addr.type == SFLADDRESSTYPE_IP_V6) {
        agentId = pcpp::IPv6Address(payload.agent_addr.address.ip_v6.addr).toString();
    }

    FlowPacket packet(agentId, stamp);

    if (_f_enabled[Filters::OnlyDeviceInterfaces]) {
        if (auto ipv4 = pcpp::IPv4Address(packet.device_id); ipv4.isValid() && std::none_of(_device_interfaces_list.begin(), _device_interfaces_list.end(), [packet](const auto &item) {
                return packet.device_id == item.first;
            })) {
            _metrics->process_filtered(stamp, payload.elements.size(), packet.device_id);
            return;
        } else if (auto ipv6 = pcpp::IPv6Address(packet.device_id); ipv6.isValid() && std::none_of(_device_interfaces_list.begin(), _device_interfaces_list.end(), [packet](const auto &item) {
                       return packet.device_id == item.first;
                   })) {
            _metrics->process_filtered(stamp, payload.elements.size(), packet.device_id);
            return;
        }
    }

    for (const auto &sample : payload.elements) {

        if (sample.sampleType == SFLCOUNTERS_SAMPLE || sample.sampleType == SFLCOUNTERS_SAMPLE_EXPANDED) {
            // skip counter flows
            continue;
        }

        FlowData flow = {};
        if (sample.gotIPV6) {
            flow.is_ipv6 = true;
        }

        flow.l4 = FLOW_IP_PROTOCOL::UNKNOWN_IP;
        switch (sample.dcd_ipProtocol) {
        case FLOW_IP_PROTOCOL::TCP:
            flow.l4 = FLOW_IP_PROTOCOL::TCP;
            break;
        case FLOW_IP_PROTOCOL::UDP:
            flow.l4 = FLOW_IP_PROTOCOL::UDP;
            break;
        }

        if (_sample_rate_scaling) {
            flow.packets = sample.meanSkipCount;
            flow.payload_size = static_cast<size_t>(sample.meanSkipCount) * sample.sampledPacketSize;
        } else {
            flow.packets = 1;
            flow.payload_size = sample.sampledPacketSize;
        }

        flow.tos = static_cast<uint8_t>(sample.dcd_ipTos);

        flow.src_port = sample.dcd_sport;
        flow.dst_port = sample.dcd_dport;
        flow.if_in_index = sample.inputPort;
        flow.if_out_index = sample.outputPort;

        if (sample.ipsrc.type == SFLADDRESSTYPE_IP_V4) {
            flow.is_ipv6 = false;
            flow.ipv4_in = pcpp::IPv4Address(sample.ipsrc.address.ip_v4.addr);

        } else if (sample.ipsrc.type == SFLADDRESSTYPE_IP_V6) {
            flow.is_ipv6 = true;
            flow.ipv6_in = pcpp::IPv6Address(sample.ipsrc.address.ip_v6.addr);
        }

        if (sample.ipdst.type == SFLADDRESSTYPE_IP_V4) {
            flow.is_ipv6 = false;
            flow.ipv4_out = pcpp::IPv4Address(sample.ipdst.address.ip_v4.addr);
        } else if (sample.ipdst.type == SFLADDRESSTYPE_IP_V6) {
            flow.is_ipv6 = true;
            flow.ipv6_out = pcpp::IPv6Address(sample.ipdst.address.ip_v6.addr);
        }

        if (!_filtering(flow, packet.device_id)) {
            packet.flow_data.push_back(flow);
        } else {
            ++packet.filtered;
        }
    }
    _metrics->process_flow(packet);
}

void FlowStreamHandler::process_netflow_cb(const std::string &senderIP, const NFSample &payload, [[maybe_unused]] size_t rawSize)
{
    timespec stamp{};
    if (payload.time_sec || payload.time_nanosec) {
        stamp.tv_sec = payload.time_sec;
        stamp.tv_nsec = payload.time_nanosec;
    } else {
        // use now()
        std::timespec_get(&stamp, TIME_UTC);
    }
    FlowPacket packet(senderIP, stamp);

    if (_f_enabled[Filters::OnlyDeviceInterfaces]) {
        if (auto ipv4 = pcpp::IPv4Address(packet.device_id); ipv4.isValid() && std::none_of(_device_interfaces_list.begin(), _device_interfaces_list.end(), [packet](const auto &item) {
                return packet.device_id == item.first;
            })) {
            _metrics->process_filtered(stamp, payload.flows.size(), packet.device_id);
            return;
        } else if (auto ipv6 = pcpp::IPv6Address(packet.device_id); ipv6.isValid() && std::none_of(_device_interfaces_list.begin(), _device_interfaces_list.end(), [packet](const auto &item) {
                       return packet.device_id == item.first;
                   })) {
            _metrics->process_filtered(stamp, payload.flows.size(), packet.device_id);
            return;
        }
    }

    for (const auto &sample : payload.flows) {
        FlowData flow = {};
        if (sample.is_ipv6) {
            flow.is_ipv6 = true;
        }

        flow.l4 = FLOW_IP_PROTOCOL::UNKNOWN_IP;
        switch (sample.protocol) {
        case FLOW_IP_PROTOCOL::TCP:
            flow.l4 = FLOW_IP_PROTOCOL::TCP;
            break;
        case FLOW_IP_PROTOCOL::UDP:
            flow.l4 = FLOW_IP_PROTOCOL::UDP;
            break;
        }

        flow.packets = sample.flow_packets;
        flow.payload_size = sample.flow_octets;
        flow.tos = sample.tos;

        flow.src_port = sample.src_port;
        flow.dst_port = sample.dst_port;
        flow.if_out_index = sample.if_index_out;
        flow.if_in_index = sample.if_index_in;

        if (sample.is_ipv6) {
            flow.ipv6_in = pcpp::IPv6Address(sample.src_ip.data());
            flow.ipv6_out = pcpp::IPv6Address(sample.dst_ip.data());
        } else {
            flow.ipv4_in = pcpp::IPv4Address(sample.src_ip.data());
            flow.ipv4_out = pcpp::IPv4Address(sample.dst_ip.data());
        }

        if (!_filtering(flow, packet.device_id)) {
            packet.flow_data.push_back(flow);
        } else {
            ++packet.filtered;
        }
    }

    _metrics->process_flow(packet);
}

bool FlowStreamHandler::_filtering(FlowData &flow, const std::string &device_id)
{
    if (_f_enabled[Filters::OnlyIps]) {
        if (flow.is_ipv6 && !match_subnet(_only_ipv6_list, flow.ipv6_in.toBytes()).has_value() && !match_subnet(_only_ipv6_list, flow.ipv6_out.toBytes()).has_value()) {
            return true;
        } else if (!match_subnet(_only_ipv4_list, flow.ipv4_in.toInt()).has_value() && !match_subnet(_only_ipv4_list, flow.ipv4_out.toInt()).has_value()) {
            return true;
        }
    }

    if (_f_enabled[Filters::OnlyPorts] && std::none_of(_parsed_port_list.begin(), _parsed_port_list.end(), [flow](auto pair) {
            return (flow.src_port >= pair.first && flow.src_port <= pair.second) || (flow.dst_port >= pair.first && flow.dst_port <= pair.second);
        })) {
        return true;
    }

    static constexpr uint8_t DEF_NO_MATCH = 2;
    if (_f_enabled[Filters::OnlyDeviceInterfaces]) {
        uint8_t no_match{0};
        if (std::none_of(_device_interfaces_list[device_id].begin(), _device_interfaces_list[device_id].end(), [flow](auto pair) {
                return (flow.if_in_index >= pair.first && flow.if_in_index <= pair.second);
            })) {
            flow.if_in_index.reset();
            ++no_match;
        }
        if (std::none_of(_device_interfaces_list[device_id].begin(), _device_interfaces_list[device_id].end(), [flow](auto pair) {
                return (flow.if_out_index >= pair.first && flow.if_out_index <= pair.second);
            })) {
            flow.if_out_index.reset();
            ++no_match;
        }
        if (no_match == DEF_NO_MATCH) {
            return true;
        }
    }

    {
        uint8_t no_match{0};
        if (_f_enabled[Filters::DisableIn]) {
            flow.if_in_index.reset();
            ++no_match;
        }

        if (_f_enabled[Filters::DisableOut]) {
            flow.if_out_index.reset();
            ++no_match;
        }
        if (no_match == DEF_NO_MATCH) {
            return true;
        }
    }

    if (_f_enabled[Filters::GeoLocNotFound] && HandlerModulePlugin::city->enabled()) {
        if (!flow.is_ipv6) {
            sockaddr_in sa4{};
            if ((lib::utils::ipv4_to_sockaddr(flow.ipv4_in, &sa4) && HandlerModulePlugin::city->getGeoLoc(&sa4).location != "Unknown")
                && (lib::utils::ipv4_to_sockaddr(flow.ipv4_out, &sa4) && HandlerModulePlugin::city->getGeoLoc(&sa4).location != "Unknown")) {
                return true;
            }
        } else {
            sockaddr_in6 sa6{};
            if ((lib::utils::ipv6_to_sockaddr(flow.ipv6_in, &sa6) && HandlerModulePlugin::city->getGeoLoc(&sa6).location != "Unknown")
                && (lib::utils::ipv6_to_sockaddr(flow.ipv6_out, &sa6) && HandlerModulePlugin::city->getGeoLoc(&sa6).location != "Unknown")) {
                return true;
            }
        }
    }
    if (_f_enabled[Filters::AsnNotFound] && HandlerModulePlugin::asn->enabled()) {
        if (!flow.is_ipv6) {
            sockaddr_in sa4{};
            if ((lib::utils::ipv4_to_sockaddr(flow.ipv4_in, &sa4) && HandlerModulePlugin::asn->getASNString(&sa4) != "Unknown")
                && (lib::utils::ipv4_to_sockaddr(flow.ipv4_out, &sa4) && HandlerModulePlugin::asn->getASNString(&sa4) != "Unknown")) {
                return true;
            }
        } else {
            sockaddr_in6 sa6{};
            if ((lib::utils::ipv6_to_sockaddr(flow.ipv6_in, &sa6) && HandlerModulePlugin::asn->getASNString(&sa6) != "Unknown")
                && (lib::utils::ipv6_to_sockaddr(flow.ipv6_out, &sa6) && HandlerModulePlugin::asn->getASNString(&sa6) != "Unknown")) {
                return true;
            }
        }
    }
    return false;
}

void FlowStreamHandler::_parse_ports(const std::vector<std::string> &port_list)
{
    for (const auto &port : port_list) {
        try {
            auto delimiter = port.find('-');
            if (delimiter != std::string::npos) {
                auto first_value = std::stoul(port.substr(0, delimiter));
                auto last_value = std::stoul(port.substr(delimiter + 1));
                if (first_value > last_value) {
                    _parsed_port_list.emplace_back(last_value, first_value);
                } else {
                    _parsed_port_list.emplace_back(first_value, last_value);
                }
            } else {
                if (!std::all_of(port.begin(), port.end(), ::isdigit)) {
                    throw StreamHandlerException("is not a digit");
                };
                auto value = std::stoul(port);
                _parsed_port_list.emplace_back(value, value);
            }
        } catch ([[maybe_unused]] const std::exception &e) {
            throw StreamHandlerException(fmt::format("FlowHandler: invalid 'only_ports' filter value: {}", port));
        }
    }
}

std::vector<std::pair<uint32_t, uint32_t>> FlowStreamHandler::_parse_interfaces(const std::vector<std::string> &interface_list)
{
    std::vector<std::pair<uint32_t, uint32_t>> result;
    for (const auto &interface : interface_list) {
        try {
            if (interface == "*") {
                // accepts all interfaces
                result = {{std::numeric_limits<uint32_t>::min(), std::numeric_limits<uint32_t>::max()}};
                return result;
            }
            auto delimiter = interface.find('-');
            if (delimiter != std::string::npos) {
                auto first_value = std::stoul(interface.substr(0, delimiter));
                auto last_value = std::stoul(interface.substr(delimiter + 1));
                if (first_value > last_value) {
                    result.emplace_back(last_value, first_value);
                } else {
                    result.emplace_back(first_value, last_value);
                }
            } else {
                if (!std::all_of(interface.begin(), interface.end(), ::isdigit)) {
                    throw StreamHandlerException("is not a digit");
                };
                auto value = std::stoul(interface);
                result.emplace_back(value, value);
            }
        } catch ([[maybe_unused]] const std::exception &e) {
            throw StreamHandlerException(fmt::format("FlowHandler: invalid 'only_device_interfaces' filter interface value: {}", interface));
        }
    }
    return result;
}

void FlowMetricsBucket::specialized_merge(const AbstractMetricsBucket &o, [[maybe_unused]] Metric::Aggregate agg_operator)
{
    // static because caller guarantees only our own bucket type
    const auto &other = static_cast<const FlowMetricsBucket &>(o);

    std::shared_lock r_lock(other._mutex);
    std::unique_lock w_lock(_mutex);

    for (const auto &device : other._devices_metrics) {
        const auto &deviceId = device.first;
        if (!_devices_metrics.count(deviceId)) {
            _devices_metrics[deviceId] = std::make_unique<FlowDevice>();
            _devices_metrics[deviceId]->set_topn_settings(_topn_count, _topn_percentile_threshold);
        }

        if (group_enabled(group::FlowMetrics::Counters)) {
            _devices_metrics[deviceId]->total += device.second->total;
            _devices_metrics[deviceId]->filtered += device.second->filtered;
        }

        if (group_enabled(group::FlowMetrics::ByBytes) && group_enabled(group::FlowMetrics::TopInterfaces)) {
            _devices_metrics[deviceId]->topInIfIndexBytes.merge(device.second->topInIfIndexBytes);
            _devices_metrics[deviceId]->topOutIfIndexBytes.merge(device.second->topOutIfIndexBytes);
        }

        if (group_enabled(group::FlowMetrics::ByPackets) && group_enabled(group::FlowMetrics::TopInterfaces)) {
            _devices_metrics[deviceId]->topInIfIndexPackets.merge(device.second->topInIfIndexPackets);
            _devices_metrics[deviceId]->topOutIfIndexPackets.merge(device.second->topOutIfIndexPackets);
        }

        for (const auto &interface : device.second->interfaces) {
            const auto &interfaceId = interface.first;
            if (!_devices_metrics[deviceId]->interfaces.count(interfaceId)) {
                _devices_metrics[deviceId]->interfaces[interfaceId] = std::make_unique<FlowInterface>();
                _devices_metrics[deviceId]->interfaces[interfaceId]->set_topn_settings(_topn_count, _topn_percentile_threshold);
            }

            auto int_if = _devices_metrics[deviceId]->interfaces[interfaceId].get();

            if (group_enabled(group::FlowMetrics::Cardinality)) {
                if (group_enabled(group::FlowMetrics::Conversations)) {
                    int_if->conversationsCard.merge(interface.second->conversationsCard);
                }
                int_if->srcIPCard.merge(interface.second->srcIPCard);
                int_if->dstIPCard.merge(interface.second->dstIPCard);
                int_if->srcPortCard.merge(interface.second->srcPortCard);
                int_if->dstPortCard.merge(interface.second->dstPortCard);
            }

            for (auto &count_dir : int_if->counters) {
                if ((count_dir.first == InBytes || count_dir.first == OutBytes) && !group_enabled(group::FlowMetrics::ByBytes)) {
                    continue;
                }
                if ((count_dir.first == InPackets || count_dir.first == OutPackets) && !group_enabled(group::FlowMetrics::ByPackets)) {
                    continue;
                }
                if (group_enabled(group::FlowMetrics::Counters)) {
                    count_dir.second.UDP += interface.second->counters.at(count_dir.first).UDP;
                    count_dir.second.TCP += interface.second->counters.at(count_dir.first).TCP;
                    count_dir.second.OtherL4 += interface.second->counters.at(count_dir.first).OtherL4;
                    count_dir.second.IPv4 += interface.second->counters.at(count_dir.first).IPv4;
                    count_dir.second.IPv6 += interface.second->counters.at(count_dir.first).IPv6;
                    count_dir.second.total += interface.second->counters.at(count_dir.first).total;
                }
            }

            for (auto &top_dir : int_if->directionTopN) {
                if ((top_dir.first == InBytes || top_dir.first == OutBytes) && !group_enabled(group::FlowMetrics::ByBytes)) {
                    continue;
                }
                if ((top_dir.first == InPackets || top_dir.first == OutPackets) && !group_enabled(group::FlowMetrics::ByPackets)) {
                    continue;
                }
                if (group_enabled(group::FlowMetrics::TopIPs)) {
                    top_dir.second.topSrcIP.merge(interface.second->directionTopN.at(top_dir.first).topSrcIP);
                    top_dir.second.topDstIP.merge(interface.second->directionTopN.at(top_dir.first).topDstIP);
                }
                if (group_enabled(group::FlowMetrics::TopPorts)) {
                    top_dir.second.topSrcPort.merge(interface.second->directionTopN.at(top_dir.first).topSrcPort);
                    top_dir.second.topDstPort.merge(interface.second->directionTopN.at(top_dir.first).topDstPort);
                }
                if (group_enabled(group::FlowMetrics::TopIPPorts)) {
                    top_dir.second.topSrcIPPort.merge(interface.second->directionTopN.at(top_dir.first).topSrcIPPort);
                    top_dir.second.topDstIPPort.merge(interface.second->directionTopN.at(top_dir.first).topDstIPPort);
                }
                if (group_enabled(group::FlowMetrics::TopTos)) {
                    top_dir.second.topDSCP.merge(interface.second->directionTopN.at(top_dir.first).topDSCP);
                    top_dir.second.topECN.merge(interface.second->directionTopN.at(top_dir.first).topECN);
                }
            }

            if (group_enabled(group::FlowMetrics::ByBytes)) {
                if (group_enabled(group::FlowMetrics::TopGeo)) {
                    int_if->topN.first.topGeoLoc.merge(interface.second->topN.first.topGeoLoc);
                    int_if->topN.first.topASN.merge(interface.second->topN.first.topASN);
                }
                if (group_enabled(group::FlowMetrics::Conversations)) {
                    int_if->topN.first.topConversations.merge(interface.second->topN.first.topConversations);
                }
            }

            if (group_enabled(group::FlowMetrics::ByPackets)) {
                if (group_enabled(group::FlowMetrics::TopGeo)) {
                    int_if->topN.second.topGeoLoc.merge(interface.second->topN.second.topGeoLoc);
                    int_if->topN.second.topASN.merge(interface.second->topN.second.topASN);
                }
                if (group_enabled(group::FlowMetrics::Conversations)) {
                    int_if->topN.second.topConversations.merge(interface.second->topN.second.topConversations);
                }
            }
        }
    }
}

void FlowMetricsBucket::to_prometheus(std::stringstream &out, Metric::LabelMap add_labels) const
{
    std::shared_lock r_lock(_mutex);

    for (const auto &device : _devices_metrics) {
        auto device_labels = add_labels;
        auto deviceId = device.first;
        DeviceEnrich *dev{nullptr};
        if (_enrich_data) {
            if (auto it = _enrich_data->find(deviceId); it != _enrich_data->end()) {
                dev = &it->second;
                deviceId = it->second.name;
            }
        }
        device_labels["device"] = deviceId;

        if (group_enabled(group::FlowMetrics::Counters)) {
            device.second->total.to_prometheus(out, device_labels);
            device.second->filtered.to_prometheus(out, device_labels);
        }

        if (group_enabled(group::FlowMetrics::ByBytes) && group_enabled(group::FlowMetrics::TopInterfaces)) {
            device.second->topInIfIndexBytes.to_prometheus(out, device_labels, [dev](const uint32_t &val) {
                if (dev) {
                    if (auto it = dev->interfaces.find(val); it != dev->interfaces.end()) {
                        return it->second.name;
                    }
                }
                return std::to_string(val);
            });
            device.second->topOutIfIndexBytes.to_prometheus(out, device_labels, [dev](const uint32_t &val) {
                if (dev) {
                    if (auto it = dev->interfaces.find(val); it != dev->interfaces.end()) {
                        return it->second.name;
                    }
                }
                return std::to_string(val);
            });
        }

        if (group_enabled(group::FlowMetrics::ByPackets) && group_enabled(group::FlowMetrics::TopInterfaces)) {
            device.second->topInIfIndexPackets.to_prometheus(out, device_labels, [dev](const uint32_t &val) {
                if (dev) {
                    if (auto it = dev->interfaces.find(val); it != dev->interfaces.end()) {
                        return it->second.name;
                    }
                }
                return std::to_string(val);
            });
            device.second->topOutIfIndexPackets.to_prometheus(out, device_labels, [dev](const uint32_t &val) {
                if (dev) {
                    if (auto it = dev->interfaces.find(val); it != dev->interfaces.end()) {
                        return it->second.name;
                    }
                }
                return std::to_string(val);
            });
        }

        for (const auto &interface : device.second->interfaces) {
            auto interface_labels = device_labels;
            std::string interfaceId = std::to_string(interface.first);
            if (dev) {
                if (auto it = dev->interfaces.find(interface.first); it != dev->interfaces.end()) {
                    interfaceId = it->second.name;
                }
            }
            interface_labels["device_interface"] = deviceId + "|" + interfaceId;

            if (group_enabled(group::FlowMetrics::Cardinality)) {
                if (group_enabled(group::FlowMetrics::Conversations)) {
                    interface.second->conversationsCard.to_prometheus(out, device_labels);
                }
                interface.second->srcIPCard.to_prometheus(out, interface_labels);
                interface.second->dstIPCard.to_prometheus(out, interface_labels);
                interface.second->srcPortCard.to_prometheus(out, interface_labels);
                interface.second->dstPortCard.to_prometheus(out, interface_labels);
            }

            for (auto &count_dir : interface.second->counters) {
                if ((count_dir.first == InBytes || count_dir.first == OutBytes) && !group_enabled(group::FlowMetrics::ByBytes)) {
                    continue;
                }
                if ((count_dir.first == InPackets || count_dir.first == OutPackets) && !group_enabled(group::FlowMetrics::ByPackets)) {
                    continue;
                }
                if (group_enabled(group::FlowMetrics::Counters)) {
                    count_dir.second.UDP.to_prometheus(out, interface_labels);
                    count_dir.second.TCP.to_prometheus(out, interface_labels);
                    count_dir.second.OtherL4.to_prometheus(out, interface_labels);
                    count_dir.second.IPv4.to_prometheus(out, interface_labels);
                    count_dir.second.IPv6.to_prometheus(out, interface_labels);
                    count_dir.second.total.to_prometheus(out, interface_labels);
                }
            }

            for (auto &top_dir : interface.second->directionTopN) {
                if ((top_dir.first == InBytes || top_dir.first == OutBytes) && !group_enabled(group::FlowMetrics::ByBytes)) {
                    continue;
                }
                if ((top_dir.first == InPackets || top_dir.first == OutPackets) && !group_enabled(group::FlowMetrics::ByPackets)) {
                    continue;
                }
                if (group_enabled(group::FlowMetrics::TopIPs)) {
                    top_dir.second.topSrcIP.to_prometheus(out, interface_labels);
                    top_dir.second.topDstIP.to_prometheus(out, interface_labels);
                }
                if (group_enabled(group::FlowMetrics::TopPorts)) {
                    top_dir.second.topSrcPort.to_prometheus(out, interface_labels);
                    top_dir.second.topDstPort.to_prometheus(out, interface_labels);
                }
                if (group_enabled(group::FlowMetrics::TopIPPorts)) {
                    top_dir.second.topSrcIPPort.to_prometheus(out, interface_labels);
                    top_dir.second.topDstIPPort.to_prometheus(out, interface_labels);
                }
                if (group_enabled(group::FlowMetrics::TopTos)) {
                    top_dir.second.topDSCP.to_prometheus(out, interface_labels, [](const uint8_t &val) {
                        if (DscpNames.find(val) != DscpNames.end()) {
                            return DscpNames[val];
                        } else {
                            return std::to_string(val);
                        }
                    });
                    top_dir.second.topECN.to_prometheus(out, interface_labels, [](const uint8_t &val) {
                        if (EcnNames.find(val) != EcnNames.end()) {
                            return EcnNames[val];
                        } else {
                            return std::to_string(val);
                        }
                    });
                }
            }

            if (group_enabled(group::FlowMetrics::ByBytes)) {
                if (group_enabled(group::FlowMetrics::TopGeo)) {
                    interface.second->topN.first.topGeoLoc.to_prometheus(out, interface_labels, [](Metric::LabelMap &l, const std::string &key, const visor::geo::City &val) {
                        l[key] = val.location;
                        if (!val.latitude.empty() && !val.longitude.empty()) {
                            l["lat"] = val.latitude;
                            l["lon"] = val.longitude;
                        }
                    });
                    interface.second->topN.first.topASN.to_prometheus(out, interface_labels);
                }
                if (group_enabled(group::FlowMetrics::Conversations)) {
                    interface.second->topN.first.topConversations.to_prometheus(out, interface_labels);
                }
            }

            if (group_enabled(group::FlowMetrics::ByPackets)) {
                if (group_enabled(group::FlowMetrics::TopGeo)) {
                    interface.second->topN.second.topGeoLoc.to_prometheus(out, interface_labels, [](Metric::LabelMap &l, const std::string &key, const visor::geo::City &val) {
                        l[key] = val.location;
                        if (!val.latitude.empty() && !val.longitude.empty()) {
                            l["lat"] = val.latitude;
                            l["lon"] = val.longitude;
                        }
                    });
                    interface.second->topN.second.topASN.to_prometheus(out, interface_labels);
                }
                if (group_enabled(group::FlowMetrics::Conversations)) {
                    interface.second->topN.second.topConversations.to_prometheus(out, interface_labels);
                }
            }
        }
    }
}

void FlowMetricsBucket::to_opentelemetry(metrics::v1::ScopeMetrics &scope, timespec &start_ts, timespec &end_ts, Metric::LabelMap add_labels) const
{
    std::shared_lock r_lock(_mutex);

    for (const auto &device : _devices_metrics) {
        auto device_labels = add_labels;
        auto deviceId = device.first;
        DeviceEnrich *dev{nullptr};
        if (_enrich_data) {
            if (auto it = _enrich_data->find(deviceId); it != _enrich_data->end()) {
                dev = &it->second;
                deviceId = it->second.name;
            }
        }
        device_labels["device"] = deviceId;

        if (group_enabled(group::FlowMetrics::Counters)) {
            device.second->total.to_opentelemetry(scope, start_ts, end_ts, device_labels);
            device.second->filtered.to_opentelemetry(scope, start_ts, end_ts, device_labels);
        }

        if (group_enabled(group::FlowMetrics::ByBytes) && group_enabled(group::FlowMetrics::TopInterfaces)) {
            device.second->topInIfIndexBytes.to_opentelemetry(scope, start_ts, end_ts, device_labels, [dev](const uint32_t &val) {
                if (dev) {
                    if (auto it = dev->interfaces.find(val); it != dev->interfaces.end()) {
                        return it->second.name;
                    }
                }
                return std::to_string(val);
            });
            device.second->topOutIfIndexBytes.to_opentelemetry(scope, start_ts, end_ts, device_labels, [dev](const uint32_t &val) {
                if (dev) {
                    if (auto it = dev->interfaces.find(val); it != dev->interfaces.end()) {
                        return it->second.name;
                    }
                }
                return std::to_string(val);
            });
        }

        if (group_enabled(group::FlowMetrics::ByPackets) && group_enabled(group::FlowMetrics::TopInterfaces)) {
            device.second->topInIfIndexPackets.to_opentelemetry(scope, start_ts, end_ts, device_labels, [dev](const uint32_t &val) {
                if (dev) {
                    if (auto it = dev->interfaces.find(val); it != dev->interfaces.end()) {
                        return it->second.name;
                    }
                }
                return std::to_string(val);
            });
            device.second->topOutIfIndexPackets.to_opentelemetry(scope, start_ts, end_ts, device_labels, [dev](const uint32_t &val) {
                if (dev) {
                    if (auto it = dev->interfaces.find(val); it != dev->interfaces.end()) {
                        return it->second.name;
                    }
                }
                return std::to_string(val);
            });
        }

        for (const auto &interface : device.second->interfaces) {
            auto interface_labels = device_labels;
            std::string interfaceId = std::to_string(interface.first);
            if (dev) {
                if (auto it = dev->interfaces.find(interface.first); it != dev->interfaces.end()) {
                    interfaceId = it->second.name;
                }
            }
            interface_labels["device_interface"] = deviceId + "|" + interfaceId;

            if (group_enabled(group::FlowMetrics::Cardinality)) {
                if (group_enabled(group::FlowMetrics::Conversations)) {
                    interface.second->conversationsCard.to_opentelemetry(scope, start_ts, end_ts, device_labels);
                }
                interface.second->srcIPCard.to_opentelemetry(scope, start_ts, end_ts, interface_labels);
                interface.second->dstIPCard.to_opentelemetry(scope, start_ts, end_ts, interface_labels);
                interface.second->srcPortCard.to_opentelemetry(scope, start_ts, end_ts, interface_labels);
                interface.second->dstPortCard.to_opentelemetry(scope, start_ts, end_ts, interface_labels);
            }

            for (auto &count_dir : interface.second->counters) {
                if ((count_dir.first == InBytes || count_dir.first == OutBytes) && !group_enabled(group::FlowMetrics::ByBytes)) {
                    continue;
                }
                if ((count_dir.first == InPackets || count_dir.first == OutPackets) && !group_enabled(group::FlowMetrics::ByPackets)) {
                    continue;
                }
                if (group_enabled(group::FlowMetrics::Counters)) {
                    count_dir.second.UDP.to_opentelemetry(scope, start_ts, end_ts, interface_labels);
                    count_dir.second.TCP.to_opentelemetry(scope, start_ts, end_ts, interface_labels);
                    count_dir.second.OtherL4.to_opentelemetry(scope, start_ts, end_ts, interface_labels);
                    count_dir.second.IPv4.to_opentelemetry(scope, start_ts, end_ts, interface_labels);
                    count_dir.second.IPv6.to_opentelemetry(scope, start_ts, end_ts, interface_labels);
                    count_dir.second.total.to_opentelemetry(scope, start_ts, end_ts, interface_labels);
                }
            }

            for (auto &top_dir : interface.second->directionTopN) {
                if ((top_dir.first == InBytes || top_dir.first == OutBytes) && !group_enabled(group::FlowMetrics::ByBytes)) {
                    continue;
                }
                if ((top_dir.first == InPackets || top_dir.first == OutPackets) && !group_enabled(group::FlowMetrics::ByPackets)) {
                    continue;
                }
                if (group_enabled(group::FlowMetrics::TopIPs)) {
                    top_dir.second.topSrcIP.to_opentelemetry(scope, start_ts, end_ts, interface_labels);
                    top_dir.second.topDstIP.to_opentelemetry(scope, start_ts, end_ts, interface_labels);
                }
                if (group_enabled(group::FlowMetrics::TopPorts)) {
                    top_dir.second.topSrcPort.to_opentelemetry(scope, start_ts, end_ts, interface_labels);
                    top_dir.second.topDstPort.to_opentelemetry(scope, start_ts, end_ts, interface_labels);
                }
                if (group_enabled(group::FlowMetrics::TopIPPorts)) {
                    top_dir.second.topSrcIPPort.to_opentelemetry(scope, start_ts, end_ts, interface_labels);
                    top_dir.second.topDstIPPort.to_opentelemetry(scope, start_ts, end_ts, interface_labels);
                }
                if (group_enabled(group::FlowMetrics::TopTos)) {
                    top_dir.second.topDSCP.to_opentelemetry(scope, start_ts, end_ts, interface_labels, [](const uint8_t &val) {
                        if (DscpNames.find(val) != DscpNames.end()) {
                            return DscpNames[val];
                        } else {
                            return std::to_string(val);
                        }
                    });
                    top_dir.second.topECN.to_opentelemetry(scope, start_ts, end_ts, interface_labels, [](const uint8_t &val) {
                        if (EcnNames.find(val) != EcnNames.end()) {
                            return EcnNames[val];
                        } else {
                            return std::to_string(val);
                        }
                    });
                }
            }

            if (group_enabled(group::FlowMetrics::ByBytes)) {
                if (group_enabled(group::FlowMetrics::TopGeo)) {
                    interface.second->topN.first.topGeoLoc.to_opentelemetry(scope, start_ts, end_ts, interface_labels, [](Metric::LabelMap &l, const std::string &key, const visor::geo::City &val) {
                        l[key] = val.location;
                        if (!val.latitude.empty() && !val.longitude.empty()) {
                            l["lat"] = val.latitude;
                            l["lon"] = val.longitude;
                        }
                    });
                    interface.second->topN.first.topASN.to_opentelemetry(scope, start_ts, end_ts, interface_labels);
                }
                if (group_enabled(group::FlowMetrics::Conversations)) {
                    interface.second->topN.first.topConversations.to_opentelemetry(scope, start_ts, end_ts, interface_labels);
                }
            }

            if (group_enabled(group::FlowMetrics::ByPackets)) {
                if (group_enabled(group::FlowMetrics::TopGeo)) {
                    interface.second->topN.second.topGeoLoc.to_opentelemetry(scope, start_ts, end_ts, interface_labels, [](Metric::LabelMap &l, const std::string &key, const visor::geo::City &val) {
                        l[key] = val.location;
                        if (!val.latitude.empty() && !val.longitude.empty()) {
                            l["lat"] = val.latitude;
                            l["lon"] = val.longitude;
                        }
                    });
                    interface.second->topN.second.topASN.to_opentelemetry(scope, start_ts, end_ts, interface_labels);
                }
                if (group_enabled(group::FlowMetrics::Conversations)) {
                    interface.second->topN.second.topConversations.to_opentelemetry(scope, start_ts, end_ts, interface_labels);
                }
            }
        }
    }
}

void FlowMetricsBucket::to_json(json &j) const
{
    std::shared_lock r_lock(_mutex);

    for (const auto &device : _devices_metrics) {
        auto deviceId = device.first;
        DeviceEnrich *dev{nullptr};
        if (_enrich_data) {
            auto it = _enrich_data->find(deviceId);
            if (it != _enrich_data->end()) {
                dev = &it->second;
                deviceId = it->second.name;
            }
        }

        if (group_enabled(group::FlowMetrics::Counters)) {
            device.second->total.to_json(j["devices"][deviceId]);
            device.second->filtered.to_json(j["devices"][deviceId]);
        }

        if (group_enabled(group::FlowMetrics::ByBytes) && group_enabled(group::FlowMetrics::TopInterfaces)) {
            device.second->topInIfIndexBytes.to_json(j["devices"][deviceId], [dev](const uint32_t &val) {
                if (dev) {
                    if (auto it = dev->interfaces.find(val); it != dev->interfaces.end()) {
                        return it->second.name;
                    }
                }
                return std::to_string(val);
            });
            device.second->topOutIfIndexBytes.to_json(j["devices"][deviceId], [dev](const uint32_t &val) {
                if (dev) {
                    if (auto it = dev->interfaces.find(val); it != dev->interfaces.end()) {
                        return it->second.name;
                    }
                }
                return std::to_string(val);
            });
        }

        if (group_enabled(group::FlowMetrics::ByPackets) && group_enabled(group::FlowMetrics::TopInterfaces)) {
            device.second->topInIfIndexPackets.to_json(j["devices"][deviceId], [dev](const uint32_t &val) {
                if (dev) {
                    if (auto it = dev->interfaces.find(val); it != dev->interfaces.end()) {
                        return it->second.name;
                    }
                }
                return std::to_string(val);
            });
            device.second->topOutIfIndexPackets.to_json(j["devices"][deviceId], [dev](const uint32_t &val) {
                if (dev) {
                    if (auto it = dev->interfaces.find(val); it != dev->interfaces.end()) {
                        return it->second.name;
                    }
                }
                return std::to_string(val);
            });
        }

        for (const auto &interface : device.second->interfaces) {
            std::string interfaceId = std::to_string(interface.first);
            if (dev) {
                if (auto it = dev->interfaces.find(interface.first); it != dev->interfaces.end()) {
                    interfaceId = it->second.name;
                }
            }

            if (group_enabled(group::FlowMetrics::Cardinality)) {
                if (group_enabled(group::FlowMetrics::Conversations)) {
                    interface.second->conversationsCard.to_json(j["devices"][deviceId]["interfaces"][interfaceId]);
                }
                interface.second->srcIPCard.to_json(j["devices"][deviceId]["interfaces"][interfaceId]);
                interface.second->dstIPCard.to_json(j["devices"][deviceId]["interfaces"][interfaceId]);
                interface.second->srcPortCard.to_json(j["devices"][deviceId]["interfaces"][interfaceId]);
                interface.second->dstPortCard.to_json(j["devices"][deviceId]["interfaces"][interfaceId]);
            }

            for (auto &count_dir : interface.second->counters) {
                if ((count_dir.first == InBytes || count_dir.first == OutBytes) && !group_enabled(group::FlowMetrics::ByBytes)) {
                    continue;
                }
                if ((count_dir.first == InPackets || count_dir.first == OutPackets) && !group_enabled(group::FlowMetrics::ByPackets)) {
                    continue;
                }
                if (group_enabled(group::FlowMetrics::Counters)) {
                    count_dir.second.UDP.to_json(j["devices"][deviceId]["interfaces"][interfaceId]);
                    count_dir.second.TCP.to_json(j["devices"][deviceId]["interfaces"][interfaceId]);
                    count_dir.second.OtherL4.to_json(j["devices"][deviceId]["interfaces"][interfaceId]);
                    count_dir.second.IPv4.to_json(j["devices"][deviceId]["interfaces"][interfaceId]);
                    count_dir.second.IPv6.to_json(j["devices"][deviceId]["interfaces"][interfaceId]);
                    count_dir.second.total.to_json(j["devices"][deviceId]["interfaces"][interfaceId]);
                }
            }

            for (auto &top_dir : interface.second->directionTopN) {
                if ((top_dir.first == InBytes || top_dir.first == OutBytes) && !group_enabled(group::FlowMetrics::ByBytes)) {
                    continue;
                }
                if ((top_dir.first == InPackets || top_dir.first == OutPackets) && !group_enabled(group::FlowMetrics::ByPackets)) {
                    continue;
                }
                if (group_enabled(group::FlowMetrics::TopIPs)) {
                    top_dir.second.topSrcIP.to_json(j["devices"][deviceId]["interfaces"][interfaceId]);
                    top_dir.second.topDstIP.to_json(j["devices"][deviceId]["interfaces"][interfaceId]);
                }
                if (group_enabled(group::FlowMetrics::TopPorts)) {
                    top_dir.second.topSrcPort.to_json(j["devices"][deviceId]["interfaces"][interfaceId]);
                    top_dir.second.topDstPort.to_json(j["devices"][deviceId]["interfaces"][interfaceId]);
                }
                if (group_enabled(group::FlowMetrics::TopIPPorts)) {
                    top_dir.second.topSrcIPPort.to_json(j["devices"][deviceId]["interfaces"][interfaceId]);
                    top_dir.second.topDstIPPort.to_json(j["devices"][deviceId]["interfaces"][interfaceId]);
                }
                if (group_enabled(group::FlowMetrics::TopTos)) {
                    top_dir.second.topDSCP.to_json(j["devices"][deviceId]["interfaces"][interfaceId], [](const uint8_t &val) {
                        if (DscpNames.find(val) != DscpNames.end()) {
                            return DscpNames[val];
                        } else {
                            return std::to_string(val);
                        }
                    });
                    top_dir.second.topECN.to_json(j["devices"][deviceId]["interfaces"][interfaceId], [](const uint8_t &val) {
                        if (EcnNames.find(val) != EcnNames.end()) {
                            return EcnNames[val];
                        } else {
                            return std::to_string(val);
                        }
                    });
                }
            }

            if (group_enabled(group::FlowMetrics::ByBytes)) {
                if (group_enabled(group::FlowMetrics::TopGeo)) {
                    interface.second->topN.first.topGeoLoc.to_json(j["devices"][deviceId]["interfaces"][interfaceId], [](json &j, const std::string &key, const visor::geo::City &val) {
                        j[key] = val.location;
                        if (!val.latitude.empty() && !val.longitude.empty()) {
                            j["lat"] = val.latitude;
                            j["lon"] = val.longitude;
                        }
                    });
                    interface.second->topN.first.topASN.to_json(j["devices"][deviceId]["interfaces"][interfaceId]);
                }
                if (group_enabled(group::FlowMetrics::Conversations)) {
                    interface.second->topN.first.topConversations.to_json(j["devices"][deviceId]["interfaces"][interfaceId]);
                }
            }

            if (group_enabled(group::FlowMetrics::ByPackets)) {
                if (group_enabled(group::FlowMetrics::TopGeo)) {
                    interface.second->topN.second.topGeoLoc.to_json(j["devices"][deviceId]["interfaces"][interfaceId], [](json &j, const std::string &key, const visor::geo::City &val) {
                        j[key] = val.location;
                        if (!val.latitude.empty() && !val.longitude.empty()) {
                            j["lat"] = val.latitude;
                            j["lon"] = val.longitude;
                        }
                    });
                    interface.second->topN.second.topASN.to_json(j["devices"][deviceId]["interfaces"][interfaceId]);
                }
                if (group_enabled(group::FlowMetrics::Conversations)) {
                    interface.second->topN.second.topConversations.to_json(j["devices"][deviceId]["interfaces"][interfaceId]);
                }
            }
        }
    }
}

void FlowMetricsBucket::process_flow(bool deep, const FlowPacket &payload, FlowCache &cache)
{
    std::unique_lock lock(_mutex);

    if (!_devices_metrics.count(payload.device_id)) {
        _devices_metrics[payload.device_id] = std::make_unique<FlowDevice>();
        _devices_metrics[payload.device_id]->set_topn_settings(_topn_count, _topn_percentile_threshold);
    }

    auto device_flow = _devices_metrics[payload.device_id].get();

    if (group_enabled(group::FlowMetrics::Counters)) {
        device_flow->filtered += payload.filtered;
    }

    for (const auto &flow : payload.flow_data) {
        if (group_enabled(group::FlowMetrics::Counters)) {
            ++device_flow->total;
        }
        if (flow.if_in_index.has_value()) {
            if (!device_flow->interfaces.count(flow.if_in_index.value())) {
                device_flow->interfaces[flow.if_in_index.value()] = std::make_unique<FlowInterface>();
                device_flow->interfaces[flow.if_in_index.value()]->set_topn_settings(_topn_count, _topn_percentile_threshold);
            }

            if (group_enabled(group::FlowMetrics::ByBytes)) {
                process_interface(deep, device_flow->interfaces[flow.if_in_index.value()].get(), flow, cache, InBytes);
                if (deep && group_enabled(group::FlowMetrics::TopInterfaces)) {
                    device_flow->topInIfIndexBytes.update(flow.if_in_index.value(), flow.payload_size);
                }
            }
            if (group_enabled(group::FlowMetrics::ByPackets)) {
                process_interface(deep, device_flow->interfaces[flow.if_in_index.value()].get(), flow, cache, InPackets);
                if (deep && group_enabled(group::FlowMetrics::TopInterfaces)) {
                    device_flow->topInIfIndexPackets.update(flow.if_in_index.value(), flow.packets);
                }
            }
        }

        if (flow.if_out_index.has_value()) {
            if (!device_flow->interfaces.count(flow.if_out_index.value())) {
                device_flow->interfaces[flow.if_out_index.value()] = std::make_unique<FlowInterface>();
                device_flow->interfaces[flow.if_out_index.value()]->set_topn_settings(_topn_count, _topn_percentile_threshold);
            }
            if (group_enabled(group::FlowMetrics::ByBytes)) {
                process_interface(deep, device_flow->interfaces[flow.if_out_index.value()].get(), flow, cache, OutBytes);
                if (deep && group_enabled(group::FlowMetrics::TopInterfaces)) {
                    device_flow->topOutIfIndexBytes.update(flow.if_out_index.value(), flow.payload_size);
                }
            }
            if (group_enabled(group::FlowMetrics::ByPackets)) {
                process_interface(deep, device_flow->interfaces[flow.if_out_index.value()].get(), flow, cache, OutPackets);
                if (deep && group_enabled(group::FlowMetrics::TopInterfaces)) {
                    device_flow->topOutIfIndexPackets.update(flow.if_out_index.value(), flow.packets);
                }
            }
        }
    }
}

void FlowMetricsBucket::process_interface(bool deep, FlowInterface *iface, const FlowData &flow, FlowCache &cache, FlowDirectionType type)
{
    uint64_t aggregator{0};
    switch (type) {
    case InBytes:
    case OutBytes:
        aggregator = flow.payload_size;
        break;
    case InPackets:
    case OutPackets:
        aggregator = flow.packets;
        break;
    }

    if (group_enabled(group::FlowMetrics::Counters)) {
        iface->counters.at(type).total += aggregator;

        if (flow.is_ipv6) {
            iface->counters.at(type).IPv6 += aggregator;
        } else {
            iface->counters.at(type).IPv4 += aggregator;
        }

        switch (flow.l4) {
        case FLOW_IP_PROTOCOL::UDP:
            iface->counters.at(type).UDP += aggregator;
            break;
        case FLOW_IP_PROTOCOL::TCP:
            iface->counters.at(type).TCP += aggregator;
            break;
        default:
            iface->counters.at(type).OtherL4 += aggregator;
            break;
        }
    }

    if (!deep) {
        return;
    }

    auto proto = network::Protocol::TCP;
    if (flow.l4 == FLOW_IP_PROTOCOL::UDP) {
        proto = network::Protocol::UDP;
    }

    std::string src_port{std::to_string(flow.src_port)};
    std::string dst_port{std::to_string(flow.dst_port)};

    if (group_enabled(group::FlowMetrics::TopPorts)) {
        if (flow.src_port > 0) {
            if (auto port = cache.lru_port_list.getValue({flow.src_port, proto}); port.has_value()) {
                src_port = port.value();
            } else {
                src_port = network::IpPort::get_service(flow.src_port, proto);
                cache.lru_port_list.put({flow.src_port, proto}, src_port);
            }
            iface->directionTopN.at(type).topSrcPort.update(src_port, aggregator);
        }
        if (flow.dst_port > 0) {
            if (auto port = cache.lru_port_list.getValue({flow.dst_port, proto}); port.has_value()) {
                dst_port = port.value();
            } else {
                dst_port = network::IpPort::get_service(flow.dst_port, proto);
                cache.lru_port_list.put({flow.dst_port, proto}, dst_port);
            }
            iface->directionTopN.at(type).topDstPort.update(dst_port, aggregator);
        }
    }

    if (group_enabled(group::FlowMetrics::Cardinality)) {
        if (flow.src_port > 0) {
            iface->srcPortCard.update(flow.src_port);
        }
        if (flow.dst_port > 0) {
            iface->dstPortCard.update(flow.dst_port);
        }
    }
    if (group_enabled(group::FlowMetrics::TopTos)) {
        iface->directionTopN.at(type).topDSCP.update((flow.tos >> DSCP_SHIFT), aggregator);
        iface->directionTopN.at(type).topECN.update((flow.tos & ECN_MASK), aggregator);
    }

    std::string application_src;
    std::string application_dst;
    std::string ip;
    if (!flow.is_ipv6 && flow.ipv4_in.isValid()) {
        group_enabled(group::FlowMetrics::Cardinality) ? iface->srcIPCard.update(flow.ipv4_in.toInt()) : void();
        if (auto ipv4 = cache.lru_ipv4_list.getValue(flow.ipv4_in.toInt()); ipv4.has_value()) {
            ip = ipv4.value();
        } else {
            ip = ip_summarization(flow.ipv4_in, _summary_data);
            cache.lru_ipv4_list.put(flow.ipv4_in.toInt(), ip);
        }
        application_src = ip + ":" + src_port;
        if (group_enabled(group::FlowMetrics::TopIPs)) {
            iface->directionTopN.at(type).topSrcIP.update(ip, aggregator);
        }
        if ((flow.src_port > 0) && group_enabled(group::FlowMetrics::TopIPPorts)) {
            iface->directionTopN.at(type).topSrcIPPort.update(application_src, aggregator);
        }
        _process_geo_metrics(iface, type, flow.ipv4_in, aggregator);
    } else if (flow.is_ipv6 && flow.ipv6_in.isValid()) {
        group_enabled(group::FlowMetrics::Cardinality) ? iface->srcIPCard.update(reinterpret_cast<const void *>(flow.ipv6_in.toBytes()), 16) : void();
        auto ipv6_str = flow.ipv6_in.toString();
        if (auto ipv6 = cache.lru_ipv6_list.getValue(ipv6_str); ipv6.has_value()) {
            ip = ipv6.value();
        } else {
            ip = ip_summarization(flow.ipv6_in, _summary_data);
            cache.lru_ipv6_list.put(ipv6_str, ip);
        }
        application_src = ip + ":" + src_port;
        if (group_enabled(group::FlowMetrics::TopIPs)) {
            iface->directionTopN.at(type).topSrcIP.update(ip, aggregator);
        }
        if ((flow.src_port > 0) && group_enabled(group::FlowMetrics::TopIPPorts)) {
            iface->directionTopN.at(type).topSrcIPPort.update(application_src, aggregator);
        }
        _process_geo_metrics(iface, type, flow.ipv6_in, aggregator);
    }
    if (!flow.is_ipv6 && flow.ipv4_out.isValid()) {
        group_enabled(group::FlowMetrics::Cardinality) ? iface->dstIPCard.update(flow.ipv4_out.toInt()) : void();
        if (auto ipv4 = cache.lru_ipv4_list.getValue(flow.ipv4_out.toInt()); ipv4.has_value()) {
            ip = ipv4.value();
        } else {
            ip = ip_summarization(flow.ipv4_out, _summary_data);
            cache.lru_ipv4_list.put(flow.ipv4_out.toInt(), ip);
        }
        application_dst = ip + ":" + dst_port;
        if (group_enabled(group::FlowMetrics::TopIPs)) {
            iface->directionTopN.at(type).topDstIP.update(ip, aggregator);
        }
        if ((flow.dst_port > 0) && group_enabled(group::FlowMetrics::TopIPPorts)) {
            iface->directionTopN.at(type).topDstIPPort.update(application_dst, aggregator);
        }
        _process_geo_metrics(iface, type, flow.ipv4_out, aggregator);
    } else if (flow.is_ipv6 && flow.ipv6_out.isValid()) {
        group_enabled(group::FlowMetrics::Cardinality) ? iface->dstIPCard.update(reinterpret_cast<const void *>(flow.ipv6_out.toBytes()), 16) : void();
        auto ipv6_str = flow.ipv6_out.toString();
        if (auto ipv6 = cache.lru_ipv6_list.getValue(ipv6_str); ipv6.has_value()) {
            ip = ipv6.value();
        } else {
            ip = ip_summarization(flow.ipv6_out, _summary_data);
            cache.lru_ipv6_list.put(ipv6_str, ip);
        }
        application_dst = ip + ":" + dst_port;
        if (group_enabled(group::FlowMetrics::TopIPs)) {
            iface->directionTopN.at(type).topDstIP.update(ip, aggregator);
        }
        if ((flow.dst_port > 0) && group_enabled(group::FlowMetrics::TopIPPorts)) {
            iface->directionTopN.at(type).topDstIPPort.update(application_dst, aggregator);
        }
        _process_geo_metrics(iface, type, flow.ipv6_out, aggregator);
    }

    if (group_enabled(group::FlowMetrics::Conversations) && flow.src_port > 0 && flow.dst_port > 0 && !application_src.empty() && !application_dst.empty()) {
        std::string conversation;
        if (application_src > application_dst) {
            conversation = application_dst + "/" + application_src;
        } else {
            conversation = application_src + "/" + application_dst;
        }
        if (group_enabled(group::FlowMetrics::Cardinality)) {
            iface->conversationsCard.update(conversation);
        }
        if (type == InBytes || type == OutBytes) {
            iface->topN.first.topConversations.update(conversation, aggregator);
        } else {
            iface->topN.second.topConversations.update(conversation, aggregator);
        }
    }
}

inline void FlowMetricsBucket::_process_geo_metrics(FlowInterface *interface, FlowDirectionType type, const pcpp::IPv4Address &ipv4, uint64_t aggregator)
{
    if ((HandlerModulePlugin::asn->enabled() || HandlerModulePlugin::city->enabled()) && group_enabled(group::FlowMetrics::TopGeo)) {
        sockaddr_in sa4{};
        if (lib::utils::ipv4_to_sockaddr(ipv4, &sa4)) {
            if (HandlerModulePlugin::city->enabled()) {
                if (type == InBytes || type == OutBytes) {
                    interface->topN.first.topGeoLoc.update(HandlerModulePlugin::city->getGeoLoc(&sa4), aggregator);
                } else {
                    interface->topN.second.topGeoLoc.update(HandlerModulePlugin::city->getGeoLoc(&sa4), aggregator);
                }
            }
            if (HandlerModulePlugin::asn->enabled()) {
                if (type == InBytes || type == OutBytes) {
                    interface->topN.first.topASN.update(HandlerModulePlugin::asn->getASNString(&sa4), aggregator);
                } else {
                    interface->topN.second.topASN.update(HandlerModulePlugin::asn->getASNString(&sa4), aggregator);
                }
            }
        }
    }
}

inline void FlowMetricsBucket::_process_geo_metrics(FlowInterface *interface, FlowDirectionType type, const pcpp::IPv6Address &ipv6, uint64_t aggregator)
{
    if ((HandlerModulePlugin::asn->enabled() || HandlerModulePlugin::city->enabled()) && group_enabled(group::FlowMetrics::TopGeo)) {
        sockaddr_in6 sa6{};
        if (lib::utils::ipv6_to_sockaddr(ipv6, &sa6)) {
            if (HandlerModulePlugin::city->enabled()) {
                if (type == InBytes || type == OutBytes) {
                    interface->topN.first.topGeoLoc.update(HandlerModulePlugin::city->getGeoLoc(&sa6), aggregator);
                } else {
                    interface->topN.second.topGeoLoc.update(HandlerModulePlugin::city->getGeoLoc(&sa6), aggregator);
                }
            }
            if (HandlerModulePlugin::asn->enabled()) {
                if (type == InBytes || type == OutBytes) {
                    interface->topN.first.topASN.update(HandlerModulePlugin::asn->getASNString(&sa6), aggregator);
                } else {
                    interface->topN.second.topASN.update(HandlerModulePlugin::asn->getASNString(&sa6), aggregator);
                }
            }
        }
    }
}

void FlowMetricsManager::process_flow(const FlowPacket &payload)
{
    new_event(payload.stamp);
    // process in the "live" bucket
    live_bucket()->process_flow(_deep_sampling_now, payload, _cache);
}
}
