#include <catch2/catch_test_macros.hpp>
#include <catch2/catch_test_visor.hpp>
#include <catch2/matchers/catch_matchers.hpp>

#include "FlowInputStream.h"
#include "FlowStreamHandler.h"
#include "IpPort.h"

using namespace visor::handler::flow;

TEST_CASE("Parse sflow stream", "[sflow][flow]")
{

    FlowInputStream stream{"sflow-test"};
    stream.config_set("flow_type", "sflow");
    stream.config_set("pcap_file", "tests/fixtures/ecmp.pcap");
    visor::network::IpPort::set_csv_iana_ports("tests/fixtures/pktvisor-port-service-names.csv");
    visor::Config c;
    auto stream_proxy = stream.add_event_proxy(c);
    c.config_set<uint64_t>("num_periods", 1);
    FlowStreamHandler flow_handler{"flow-test", stream_proxy, &c};
    flow_handler.config_set<visor::Configurable::StringList>("enable", visor::Configurable::StringList({"top_tos"}));

    flow_handler.start();
    stream.start();
    stream.stop();
    flow_handler.stop();

    auto event_data = flow_handler.metrics()->bucket(0)->event_data_locked();

    // confirmed with wireshark
    CHECK(event_data.num_events->value() == 9279);
    CHECK(event_data.num_samples->value() == 9279);

    nlohmann::json j;
    flow_handler.metrics()->bucket(0)->to_json(j);

    CHECK(j["devices"]["192.168.0.13"]["interfaces"]["52"]["cardinality"]["dst_ips_out"] == 4);
    CHECK(j["devices"]["192.168.0.13"]["interfaces"]["52"]["cardinality"]["src_ips_in"] == 4);
    CHECK(j["devices"]["192.168.0.13"]["interfaces"]["52"]["cardinality"]["dst_ports_out"] == 23);
    CHECK(j["devices"]["192.168.0.13"]["interfaces"]["52"]["cardinality"]["src_ports_in"] == 9);
    CHECK(j["devices"]["192.168.0.13"]["interfaces"]["52"]["top_in_src_ips_bytes"][0]["estimate"] == 108027400000);
    CHECK(j["devices"]["192.168.0.13"]["interfaces"]["52"]["top_in_src_ips_bytes"][0]["name"] == "10.4.1.2");
    CHECK(j["devices"]["192.168.0.13"]["interfaces"]["52"]["top_out_src_ips_packets"][0]["estimate"] == 5160000);
    CHECK(j["devices"]["192.168.0.13"]["interfaces"]["52"]["top_out_src_ips_packets"][0]["name"] == "10.4.4.2");
    CHECK(j["devices"]["192.168.0.13"]["interfaces"]["52"]["top_in_dst_ports_bytes"][0]["estimate"] == 170879120000);
    CHECK(j["devices"]["192.168.0.13"]["interfaces"]["52"]["top_in_dst_ports_bytes"][0]["name"] == "commplex-link");
    CHECK(j["devices"]["192.168.0.13"]["interfaces"]["52"]["top_in_src_ports_bytes"][0]["name"] == "dynamic-client");
    CHECK(j["devices"]["192.168.0.13"]["interfaces"]["52"]["top_in_src_ip_ports_bytes"][0]["estimate"] == 108027400000);
    CHECK(j["devices"]["192.168.0.13"]["interfaces"]["52"]["top_in_src_ip_ports_bytes"][0]["name"] == "10.4.1.2:dynamic-client");
    CHECK(j["devices"]["192.168.0.13"]["interfaces"]["52"]["top_in_dscp_bytes"][0]["estimate"] == 170879120000);
    CHECK(j["devices"]["192.168.0.13"]["interfaces"]["52"]["top_in_dscp_bytes"][0]["name"] == "CS0");
    CHECK(j["devices"]["192.168.0.13"]["interfaces"]["52"]["top_in_ecn_packets"][0]["estimate"] == 112600000);
    CHECK(j["devices"]["192.168.0.13"]["interfaces"]["52"]["top_in_ecn_packets"][0]["name"] == "ECT(0)");
}

TEST_CASE("Parse sflow with enrichment", "[sflow][flow]")
{
    FlowInputStream stream{"sflow-test"};
    stream.config_set("flow_type", "sflow");
    stream.config_set("pcap_file", "tests/fixtures/ecmp.pcap");

    visor::Config c;
    auto stream_proxy = stream.add_event_proxy(c);
    c.config_set<uint64_t>("num_periods", 1);
    FlowStreamHandler flow_handler{"flow-test", stream_proxy, &c};
    auto device_map = std::make_shared<visor::Configurable>();

    auto device = std::make_shared<visor::Configurable>();
    device->config_set("name", "route1");
    device->config_set("description", "cisco");
    auto interface = std::make_shared<visor::Configurable>();
    interface->config_set("name", "eth0");
    interface->config_set("description", "provide Y");
    auto interfaces_map = std::make_shared<visor::Configurable>();
    interfaces_map->config_set<std::shared_ptr<visor::Configurable>>("37", interface);
    device->config_set<std::shared_ptr<visor::Configurable>>("interfaces", interfaces_map);
    device_map->config_set<std::shared_ptr<visor::Configurable>>("192.168.0.11", device);

    device = std::make_shared<visor::Configurable>();
    device->config_set("name", "route2");
    interface = std::make_shared<visor::Configurable>();
    interface->config_set("name", "eth3");
    interfaces_map = std::make_shared<visor::Configurable>();
    interfaces_map->config_set<std::shared_ptr<visor::Configurable>>("4", interface);
    device->config_set<std::shared_ptr<visor::Configurable>>("interfaces", interfaces_map);
    device_map->config_set<std::shared_ptr<visor::Configurable>>("192.168.0.12", device);

    flow_handler.config_set<std::shared_ptr<visor::Configurable>>("device_map", device_map);

    auto devices = std::make_shared<visor::Configurable>();
    devices->config_set<visor::Configurable::StringList>("192.168.0.11", {"37", "4", "52"});
    devices->config_set<visor::Configurable::StringList>("192.168.0.12", {"37", "4", "52"});
    devices->config_set<visor::Configurable::StringList>("192.168.0.13", {"37", "4", "52"});
    flow_handler.config_set<std::shared_ptr<visor::Configurable>>("only_device_interfaces", devices);
    flow_handler.config_set<visor::Configurable::StringList>("enable", visor::Configurable::StringList({"top_interfaces"}));

    flow_handler.start();
    stream.start();
    stream.stop();
    flow_handler.stop();

    auto event_data = flow_handler.metrics()->bucket(0)->event_data_locked();

    // confirmed with wireshark
    CHECK(event_data.num_events->value() == 9279);
    CHECK(event_data.num_samples->value() == 9279);

    nlohmann::json j;
    flow_handler.metrics()->bucket(0)->to_json(j);
    CHECK(j["devices"]["route1"]["top_in_interfaces_bytes"][0]["name"] == "eth0");
    CHECK(j["devices"]["route2"]["top_in_interfaces_bytes"][0]["name"] == "eth3");
    CHECK(j["devices"]["192.168.0.13"]["top_in_interfaces_bytes"][0]["name"] == "52");
}

TEST_CASE("Parse sflow stream without sampling", "[sflow][flow]")
{

    FlowInputStream stream{"sflow-test"};
    stream.config_set("flow_type", "sflow");
    stream.config_set("pcap_file", "tests/fixtures/ecmp.pcap");
    visor::network::IpPort::set_csv_iana_ports("tests/fixtures/pktvisor-port-service-names.csv");

    visor::Config c;
    auto stream_proxy = stream.add_event_proxy(c);
    c.config_set<uint64_t>("num_periods", 1);
    FlowStreamHandler flow_handler{"flow-test", stream_proxy, &c};
    flow_handler.config_set<bool>("sample_rate_scaling", false);

    flow_handler.start();
    stream.start();
    stream.stop();
    flow_handler.stop();

    auto event_data = flow_handler.metrics()->bucket(0)->event_data_locked();

    // confirmed with wireshark
    CHECK(event_data.num_events->value() == 9279);
    CHECK(event_data.num_samples->value() == 9279);

    nlohmann::json j;
    flow_handler.metrics()->bucket(0)->to_json(j);

    CHECK(j["devices"]["192.168.0.13"]["interfaces"]["52"]["cardinality"]["dst_ips_out"] == 4);
    CHECK(j["devices"]["192.168.0.13"]["interfaces"]["52"]["cardinality"]["src_ips_in"] == 4);
    CHECK(j["devices"]["192.168.0.13"]["interfaces"]["52"]["cardinality"]["dst_ports_out"] == 23);
    CHECK(j["devices"]["192.168.0.13"]["interfaces"]["52"]["cardinality"]["src_ports_in"] == 9);
    CHECK(j["devices"]["192.168.0.13"]["interfaces"]["52"]["top_in_src_ips_bytes"][0]["estimate"] == 5401370);
    CHECK(j["devices"]["192.168.0.13"]["interfaces"]["52"]["top_in_src_ips_bytes"][0]["name"] == "10.4.1.2");
    CHECK(j["devices"]["192.168.0.13"]["interfaces"]["52"]["top_out_src_ips_packets"][0]["estimate"] == 258);
    CHECK(j["devices"]["192.168.0.13"]["interfaces"]["52"]["top_out_src_ips_packets"][0]["name"] == "10.4.4.2");
    CHECK(j["devices"]["192.168.0.13"]["interfaces"]["52"]["top_out_dst_ports_bytes"][0]["estimate"] == 18060);
    CHECK(j["devices"]["192.168.0.13"]["interfaces"]["52"]["top_out_src_ip_ports_bytes"][0]["estimate"] == 18060);
    CHECK(j["devices"]["192.168.0.13"]["interfaces"]["52"]["top_out_src_ip_ports_bytes"][0]["name"] == "10.4.4.2:commplex-link");
}

TEST_CASE("Parse sflow stream with ip filter", "[sflow][flow]")
{

    FlowInputStream stream{"sflow-test"};
    stream.config_set("flow_type", "sflow");
    stream.config_set("pcap_file", "tests/fixtures/ecmp.pcap");

    visor::Config c;
    auto stream_proxy = stream.add_event_proxy(c);
    c.config_set<uint64_t>("num_periods", 1);
    FlowStreamHandler flow_handler{"flow-test", stream_proxy, &c};
    flow_handler.config_set<visor::Configurable::StringList>("only_ips", {"10.4.3.2/24"});

    flow_handler.start();
    stream.start();
    stream.stop();
    flow_handler.stop();

    auto event_data = flow_handler.metrics()->bucket(0)->event_data_locked();

    // confirmed with wireshark
    CHECK(event_data.num_events->value() == 9279);
    CHECK(event_data.num_samples->value() == 9279);

    nlohmann::json j;
    flow_handler.metrics()->bucket(0)->to_json(j);

    CHECK(j["devices"]["192.168.0.13"]["interfaces"]["52"]["cardinality"]["dst_ips_out"] == 2);
    CHECK(j["devices"]["192.168.0.13"]["interfaces"]["52"]["cardinality"]["src_ips_in"] == 2);
    CHECK(j["devices"]["192.168.0.13"]["interfaces"]["52"]["cardinality"]["dst_ports_out"] == 13);
    CHECK(j["devices"]["192.168.0.13"]["interfaces"]["52"]["cardinality"]["src_ports_in"] == 4);
    CHECK(j["devices"]["192.168.0.13"]["interfaces"]["52"]["top_in_src_ips_bytes"][0]["estimate"] == 62851720000);
    CHECK(j["devices"]["192.168.0.13"]["interfaces"]["52"]["top_in_src_ips_bytes"][0]["name"] == "10.4.3.2");
    CHECK(j["devices"]["192.168.0.13"]["interfaces"]["52"]["top_out_src_ips_packets"][0]["estimate"] == 5160000);
    CHECK(j["devices"]["192.168.0.13"]["interfaces"]["52"]["top_out_src_ips_packets"][0]["name"] == "10.4.4.2");
    CHECK(j["devices"]["192.168.0.13"]["interfaces"]["52"]["top_in_dst_ports_bytes"][0]["estimate"] == 62851720000);
    CHECK(j["devices"]["192.168.0.13"]["interfaces"]["52"]["top_in_src_ip_ports_bytes"][0]["estimate"] == 62851720000);
    CHECK(j["devices"]["192.168.0.13"]["interfaces"]["52"]["top_in_src_ip_ports_bytes"][0]["name"] == "10.4.3.2:registered-40k");
}

TEST_CASE("Parse sflow stream with device filter", "[sflow][flow]")
{

    FlowInputStream stream{"sflow-test"};
    stream.config_set("flow_type", "sflow");
    stream.config_set("pcap_file", "tests/fixtures/ecmp.pcap");

    visor::Config c;
    auto stream_proxy = stream.add_event_proxy(c);
    c.config_set<uint64_t>("num_periods", 1);
    FlowStreamHandler flow_handler{"flow-test", stream_proxy, &c};
    auto devices = std::make_shared<visor::Configurable>();
    devices->config_set<visor::Configurable::StringList>("192.168.0.11", {"*"});
    flow_handler.config_set<std::shared_ptr<visor::Configurable>>("only_device_interfaces", devices);

    flow_handler.start();
    stream.start();
    stream.stop();
    flow_handler.stop();

    auto event_data = flow_handler.metrics()->bucket(0)->event_data_locked();

    // confirmed with wireshark
    CHECK(event_data.num_events->value() == 9279);
    CHECK(event_data.num_samples->value() == 9279);

    nlohmann::json j;
    flow_handler.metrics()->bucket(0)->to_json(j);

    CHECK(j["devices"]["192.168.0.11"]["interfaces"]["37"]["cardinality"]["dst_ips_out"] == 2);
    CHECK(j["devices"]["192.168.0.11"]["interfaces"]["37"]["cardinality"]["src_ips_in"] == 2);
    CHECK(j["devices"]["192.168.0.11"]["interfaces"]["37"]["cardinality"]["dst_ports_out"] == 16);
    CHECK(j["devices"]["192.168.0.11"]["interfaces"]["37"]["cardinality"]["src_ports_in"] == 16);
    CHECK(j["devices"]["192.168.0.11"]["interfaces"]["37"]["top_in_src_ips_bytes"][0]["estimate"] == 264021720000);
    CHECK(j["devices"]["192.168.0.11"]["interfaces"]["37"]["top_in_src_ips_bytes"][0]["name"] == "10.4.1.2");
    CHECK(j["devices"]["192.168.0.11"]["interfaces"]["37"]["top_out_src_ips_packets"][0]["estimate"] == 8040000);
    CHECK(j["devices"]["192.168.0.11"]["interfaces"]["37"]["top_out_src_ips_packets"][0]["name"] == "10.4.2.2");
    CHECK(j["devices"]["192.168.0.11"]["interfaces"]["37"]["top_in_dst_ports_bytes"][0]["estimate"] == 264021720000);
    CHECK(j["devices"]["192.168.0.11"]["interfaces"]["37"]["top_out_src_ip_ports_bytes"][0]["estimate"] == 563840000);
    CHECK(j["devices"]["192.168.0.11"]["interfaces"]["37"]["top_out_src_ip_ports_bytes"][0]["name"] == "10.4.2.2:commplex-link");

    CHECK(j["devices"]["192.168.0.13"]["records_filtered"] == 7189);
}

TEST_CASE("Parse sflow stream with port filter", "[sflow][flow]")
{

    FlowInputStream stream{"sflow-test"};
    stream.config_set("flow_type", "sflow");
    stream.config_set("pcap_file", "tests/fixtures/ecmp.pcap");

    visor::Config c;
    auto stream_proxy = stream.add_event_proxy(c);
    c.config_set<uint64_t>("num_periods", 1);
    FlowStreamHandler flow_handler{"flow-test", stream_proxy, &c};
    flow_handler.config_set<visor::Configurable::StringList>("only_ports", {"40265", "40400-40500"});

    flow_handler.start();
    stream.start();
    stream.stop();
    flow_handler.stop();

    auto event_data = flow_handler.metrics()->bucket(0)->event_data_locked();

    // confirmed with wireshark
    CHECK(event_data.num_events->value() == 9279);
    CHECK(event_data.num_samples->value() == 9279);

    nlohmann::json j;
    flow_handler.metrics()->bucket(0)->to_json(j);

    CHECK(j["devices"]["192.168.0.11"]["records_flows"] == 892);
    CHECK(j["devices"]["192.168.0.11"]["interfaces"]["37"] == nullptr);
    CHECK(j["devices"]["192.168.0.11"]["interfaces"]["38"]["cardinality"]["dst_ips_out"] == 2);
    CHECK(j["devices"]["192.168.0.11"]["interfaces"]["38"]["cardinality"]["src_ips_in"] == 2);
    CHECK(j["devices"]["192.168.0.11"]["interfaces"]["38"]["cardinality"]["dst_ports_out"] == 2);
    CHECK(j["devices"]["192.168.0.11"]["interfaces"]["38"]["cardinality"]["src_ports_in"] == 2);
    CHECK(j["devices"]["192.168.0.11"]["interfaces"]["38"]["top_out_src_ips_bytes"][0]["estimate"] == 71400000);
    CHECK(j["devices"]["192.168.0.11"]["interfaces"]["38"]["top_out_src_ips_bytes"][0]["name"] == "10.4.4.2");
    CHECK(j["devices"]["192.168.0.11"]["interfaces"]["38"]["top_in_src_ips_packets"][0]["estimate"] == 16820000);
    CHECK(j["devices"]["192.168.0.11"]["interfaces"]["38"]["top_in_src_ips_packets"][0]["name"] == "10.4.3.2");
    CHECK(j["devices"]["192.168.0.11"]["interfaces"]["38"]["top_in_dst_ports_bytes"][0]["estimate"] == 25532760000);
    CHECK(j["devices"]["192.168.0.11"]["interfaces"]["38"]["top_out_src_ip_ports_bytes"][0]["estimate"] == 71400000);
    CHECK(j["devices"]["192.168.0.11"]["interfaces"]["38"]["top_out_src_ip_ports_bytes"][0]["name"] == "10.4.4.2:commplex-link");
}

TEST_CASE("Parse sflow stream with subnet summary", "[sflow][flow]")
{

    FlowInputStream stream{"sflow-test"};
    stream.config_set("flow_type", "sflow");
    stream.config_set("pcap_file", "tests/fixtures/ecmp.pcap");

    visor::Config c;
    auto stream_proxy = stream.add_event_proxy(c);
    c.config_set<uint64_t>("num_periods", 1);
    FlowStreamHandler flow_handler{"flow-test", stream_proxy, &c};
    flow_handler.config_set<visor::Configurable::StringList>("subnets_for_summarization", {"10.4.0.0/16"});
    flow_handler.config_set<visor::Configurable::StringList>("exclude_ips_from_summarization", {"10.4.4.0/24"});
    flow_handler.start();
    stream.start();
    stream.stop();
    flow_handler.stop();

    auto event_data = flow_handler.metrics()->bucket(0)->event_data_locked();

    // confirmed with wireshark
    CHECK(event_data.num_events->value() == 9279);
    CHECK(event_data.num_samples->value() == 9279);

    nlohmann::json j;
    flow_handler.metrics()->bucket(0)->to_json(j);

    CHECK(j["devices"]["192.168.0.11"]["interfaces"]["4"]["top_in_src_ips_bytes"][0]["estimate"] == 399800000);
    CHECK(j["devices"]["192.168.0.11"]["interfaces"]["4"]["top_in_src_ips_bytes"][0]["name"] == "10.4.4.2");
    CHECK(j["devices"]["192.168.0.11"]["interfaces"]["38"]["top_in_src_ips_bytes"][0]["estimate"] == 249921240000);
    CHECK(j["devices"]["192.168.0.11"]["interfaces"]["38"]["top_in_src_ips_bytes"][0]["name"] == "10.4.0.0/16");
}

TEST_CASE("Parse sflow stream with subnet summary wildcard", "[sflow][flow]")
{

    FlowInputStream stream{"sflow-test"};
    stream.config_set("flow_type", "sflow");
    stream.config_set("pcap_file", "tests/fixtures/ecmp.pcap");

    visor::Config c;
    auto stream_proxy = stream.add_event_proxy(c);
    c.config_set<uint64_t>("num_periods", 1);
    FlowStreamHandler flow_handler{"flow-test", stream_proxy, &c};
    flow_handler.config_set<visor::Configurable::StringList>("subnets_for_summarization", {"0.0.0.0/16"});
    flow_handler.start();
    stream.start();
    stream.stop();
    flow_handler.stop();

    auto event_data = flow_handler.metrics()->bucket(0)->event_data_locked();

    // confirmed with wireshark
    CHECK(event_data.num_events->value() == 9279);
    CHECK(event_data.num_samples->value() == 9279);

    nlohmann::json j;
    flow_handler.metrics()->bucket(0)->to_json(j);

    CHECK(j["devices"]["192.168.0.11"]["interfaces"]["4"]["top_in_src_ips_bytes"][0]["estimate"] == 738240000);
    CHECK(j["devices"]["192.168.0.11"]["interfaces"]["4"]["top_in_src_ips_bytes"][0]["name"] == "10.4.0.0/16");
    CHECK(j["devices"]["192.168.0.11"]["interfaces"]["38"]["top_in_src_ips_bytes"][0]["estimate"] == 249921240000);
    CHECK(j["devices"]["192.168.0.11"]["interfaces"]["38"]["top_in_src_ips_bytes"][0]["name"] == "10.4.0.0/16");
}

TEST_CASE("Flow handler error with multiple wildcards", "[sflow][flow]")
{
    FlowInputStream stream{"sflow-test"};
    stream.config_set("flow_type", "sflow");
    stream.config_set("pcap_file", "tests/fixtures/ecmp.pcap");

    visor::Config c;
    auto stream_proxy = stream.add_event_proxy(c);
    c.config_set<uint64_t>("num_periods", 1);
    FlowStreamHandler flow_handler{"flow-test", stream_proxy, &c};
    flow_handler.config_set<visor::Configurable::StringList>("subnets_for_summarization", {"0.0.0.0/16", "0.0.0.0/24"});
    REQUIRE_THROWS_WITH(flow_handler.start(), "FlowHandler: 'subnets_for_summarization' only allows one ipv4 and one ipv6 wildcard");
}

TEST_CASE("Parse sflow stream with interfaces filter", "[sflow][flow]")
{

    FlowInputStream stream{"sflow-test"};
    stream.config_set("flow_type", "sflow");
    stream.config_set("pcap_file", "tests/fixtures/ecmp.pcap");

    visor::Config c;
    auto stream_proxy = stream.add_event_proxy(c);
    c.config_set<uint64_t>("num_periods", 1);
    FlowStreamHandler flow_handler{"flow-test", stream_proxy, &c};
    auto devices = std::make_shared<visor::Configurable>();
    devices->config_set<visor::Configurable::StringList>("192.168.0.11", {"37", "4", "35-37"});
    flow_handler.config_set<std::shared_ptr<visor::Configurable>>("only_device_interfaces", devices);
    flow_handler.config_set<visor::Configurable::StringList>("only_directions", {"in"});

    flow_handler.start();
    stream.start();
    stream.stop();
    flow_handler.stop();

    auto event_data = flow_handler.metrics()->bucket(0)->event_data_locked();

    // confirmed with wireshark
    CHECK(event_data.num_events->value() == 9279);
    CHECK(event_data.num_samples->value() == 9279);

    nlohmann::json j;
    flow_handler.metrics()->bucket(0)->to_json(j);

    CHECK(j["devices"]["192.168.0.11"]["interfaces"]["37"]["cardinality"]["dst_ips_out"] == 1);
    CHECK(j["devices"]["192.168.0.11"]["interfaces"]["37"]["cardinality"]["src_ips_in"] == 1);
    CHECK(j["devices"]["192.168.0.11"]["interfaces"]["37"]["cardinality"]["dst_ports_out"] == 1);
    CHECK(j["devices"]["192.168.0.11"]["interfaces"]["37"]["cardinality"]["src_ports_in"] == 15);
    CHECK(j["devices"]["192.168.0.11"]["interfaces"]["37"]["top_in_src_ips_bytes"][0]["estimate"] == 264021720000);
    CHECK(j["devices"]["192.168.0.11"]["interfaces"]["37"]["top_in_src_ips_bytes"][0]["name"] == "10.4.1.2");
    CHECK(j["devices"]["192.168.0.11"]["interfaces"]["37"]["top_out_src_ips_packets"][0]["name"] == nullptr);
    CHECK(j["devices"]["192.168.0.11"]["interfaces"]["37"]["top_out_src_ips_and_port_bytes"][0]["estimate"] == nullptr);
}

TEST_CASE("Parse netflow v5 stream", "[netflow][flow]")
{

    FlowInputStream stream{"netflow-test"};
    stream.config_set("flow_type", "netflow");
    stream.config_set("pcap_file", "tests/fixtures/nf5.pcap");

    visor::Config c;
    auto stream_proxy = stream.add_event_proxy(c);
    c.config_set<uint64_t>("num_periods", 1);
    FlowStreamHandler flow_handler{"flow-test", stream_proxy, &c};
    flow_handler.config_set<visor::Configurable::StringList>("enable", visor::Configurable::StringList({"top_tos"}));

    flow_handler.start();
    stream.start();
    stream.stop();
    flow_handler.stop();

    auto event_data = flow_handler.metrics()->bucket(0)->event_data_locked();

    // confirmed with wireshark
    CHECK(event_data.num_events->value() == 2);
    CHECK(event_data.num_samples->value() == 2);

    nlohmann::json j;
    flow_handler.metrics()->bucket(0)->to_json(j);

    CHECK(j["devices"]["10.0.0.2"]["records_flows"] == 3);
    CHECK(j["devices"]["10.0.0.2"]["interfaces"]["0"]["cardinality"]["dst_ips_out"] == 2);
    CHECK(j["devices"]["10.0.0.2"]["interfaces"]["0"]["cardinality"]["src_ips_in"] == 1);
    CHECK(j["devices"]["10.0.0.2"]["interfaces"]["0"]["cardinality"]["dst_ports_out"] == 3);
    CHECK(j["devices"]["10.0.0.2"]["interfaces"]["0"]["cardinality"]["src_ports_in"] == 2);
    CHECK(j["devices"]["10.0.0.2"]["interfaces"]["0"]["top_in_src_ips_bytes"][0]["estimate"] == 1720);
    CHECK(j["devices"]["10.0.0.2"]["interfaces"]["0"]["top_in_src_ips_packets"][0]["estimate"] == 33);
    CHECK(j["devices"]["10.0.0.2"]["interfaces"]["0"]["top_in_dscp_bytes"][0]["estimate"] == 1220);
    CHECK(j["devices"]["10.0.0.2"]["interfaces"]["0"]["top_in_dscp_bytes"][0]["name"] == "CS6");
    CHECK(j["devices"]["10.0.0.2"]["interfaces"]["0"]["top_in_ecn_packets"][0]["estimate"] == 33);
    CHECK(j["devices"]["10.0.0.2"]["interfaces"]["0"]["top_in_ecn_packets"][0]["name"] == "Not-ECT");
    CHECK(j["devices"]["10.0.0.2"]["interfaces"]["0"]["top_in_dst_ports_bytes"][0]["estimate"] == 1128);
    CHECK(j["devices"]["10.0.0.2"]["interfaces"]["0"]["top_in_dst_ports_bytes"][0]["name"] == "telnet");
}

TEST_CASE("Parse netflow v9 stream", "[netflow][flow]")
{

    FlowInputStream stream{"netflow-test"};
    stream.config_set("flow_type", "netflow");
    stream.config_set("pcap_file", "tests/fixtures/nf9.pcap");

    visor::Config c;
    auto stream_proxy = stream.add_event_proxy(c);
    c.config_set<uint64_t>("num_periods", 1);
    FlowStreamHandler flow_handler{"flow-test", stream_proxy, &c};
    flow_handler.config_set<visor::Configurable::StringList>("enable", visor::Configurable::StringList({"top_tos"}));

    flow_handler.start();
    stream.start();
    stream.stop();
    flow_handler.stop();

    auto event_data = flow_handler.metrics()->bucket(0)->event_data_locked();

    // confirmed with wireshark
    CHECK(event_data.num_events->value() == 1);
    CHECK(event_data.num_samples->value() == 1);

    nlohmann::json j;
    flow_handler.metrics()->bucket(0)->to_json(j);

    CHECK(j["devices"]["192.168.100.1"]["records_flows"] == 24);
    CHECK(j["devices"]["192.168.100.1"]["interfaces"]["800"]["cardinality"]["dst_ips_out"] == 24);
    CHECK(j["devices"]["192.168.100.1"]["interfaces"]["800"]["cardinality"]["src_ips_in"] == 24);
    CHECK(j["devices"]["192.168.100.1"]["interfaces"]["800"]["cardinality"]["dst_ports_out"] == 0);
    CHECK(j["devices"]["192.168.100.1"]["interfaces"]["800"]["cardinality"]["src_ports_in"] == 0);
    CHECK(j["devices"]["192.168.100.1"]["interfaces"]["800"]["top_in_src_ips_bytes"][0]["estimate"] == 6066232);
    CHECK(j["devices"]["192.168.100.1"]["interfaces"]["800"]["top_in_src_ips_packets"][0]["estimate"] == 7858);
    CHECK(j["devices"]["192.168.100.1"]["interfaces"]["800"]["top_in_dscp_bytes"][0]["estimate"] == 142139882);
    CHECK(j["devices"]["192.168.100.1"]["interfaces"]["800"]["top_in_dscp_bytes"][0]["name"] == "CS0");
    CHECK(j["devices"]["192.168.100.1"]["interfaces"]["800"]["top_in_ecn_packets"][0]["estimate"] == 183920);
    CHECK(j["devices"]["192.168.100.1"]["interfaces"]["800"]["top_in_ecn_packets"][0]["name"] == "Not-ECT");
}

TEST_CASE("Parse IPFIX stream", "[netflow][flow]")
{

    FlowInputStream stream{"ipfix-test"};
    stream.config_set("flow_type", "netflow");
    stream.config_set("pcap_file", "tests/fixtures/ipfix.pcap");

    visor::Config c;
    auto stream_proxy = stream.add_event_proxy(c);
    c.config_set<uint64_t>("num_periods", 1);
    FlowStreamHandler flow_handler{"flow-test", stream_proxy, &c};

    flow_handler.start();
    stream.start();
    stream.stop();
    flow_handler.stop();

    auto event_data = flow_handler.metrics()->bucket(0)->event_data_locked();

    // confirmed with wireshark
    CHECK(event_data.num_events->value() == 23);
    CHECK(event_data.num_samples->value() == 23);

    nlohmann::json j;
    flow_handler.metrics()->bucket(0)->to_json(j);

    CHECK(j["devices"]["192.168.100.2"]["records_flows"] == 23);
    CHECK(j["devices"]["192.168.100.2"]["interfaces"]["0"]["cardinality"]["dst_ips_out"] == 1);
    CHECK(j["devices"]["192.168.100.2"]["interfaces"]["0"]["cardinality"]["src_ips_in"] == 1);
    CHECK(j["devices"]["192.168.100.2"]["interfaces"]["0"]["cardinality"]["dst_ports_out"] == 9);
    CHECK(j["devices"]["192.168.100.2"]["interfaces"]["0"]["cardinality"]["src_ports_in"] == 16);
    CHECK(j["devices"]["192.168.100.2"]["interfaces"]["0"]["top_out_src_ips_bytes"][0]["estimate"] == 120000);
    CHECK(j["devices"]["192.168.100.2"]["interfaces"]["0"]["top_out_src_ips_bytes"][0]["name"] == "::1");
    CHECK(j["devices"]["192.168.100.2"]["interfaces"]["0"]["top_out_src_ips_packets"][0]["estimate"] == 1472);
}

TEST_CASE("Parse IPFIX stream with subnet summary wildcard", "[netflow][flow]")
{

    FlowInputStream stream{"ipfix-test"};
    stream.config_set("flow_type", "netflow");
    stream.config_set("pcap_file", "tests/fixtures/ipfix.pcap");

    visor::Config c;
    auto stream_proxy = stream.add_event_proxy(c);
    c.config_set<uint64_t>("num_periods", 1);
    FlowStreamHandler flow_handler{"flow-test", stream_proxy, &c};
    flow_handler.config_set<visor::Configurable::StringList>("subnets_for_summarization", {"0.0.0.0/16", "::0/24"});

    flow_handler.start();
    stream.start();
    stream.stop();
    flow_handler.stop();

    auto event_data = flow_handler.metrics()->bucket(0)->event_data_locked();

    // confirmed with wireshark
    CHECK(event_data.num_events->value() == 23);
    CHECK(event_data.num_samples->value() == 23);

    nlohmann::json j;
    flow_handler.metrics()->bucket(0)->to_json(j);

    CHECK(j["devices"]["192.168.100.2"]["records_flows"] == 23);
    CHECK(j["devices"]["192.168.100.2"]["interfaces"]["0"]["cardinality"]["dst_ips_out"] == 1);
    CHECK(j["devices"]["192.168.100.2"]["interfaces"]["0"]["cardinality"]["src_ips_in"] == 1);
    CHECK(j["devices"]["192.168.100.2"]["interfaces"]["0"]["cardinality"]["dst_ports_out"] == 9);
    CHECK(j["devices"]["192.168.100.2"]["interfaces"]["0"]["cardinality"]["src_ports_in"] == 16);
    CHECK(j["devices"]["192.168.100.2"]["interfaces"]["0"]["top_out_src_ips_bytes"][0]["estimate"] == 120000);
    CHECK(j["devices"]["192.168.100.2"]["interfaces"]["0"]["top_out_src_ips_bytes"][0]["name"] == "::/24");
    CHECK(j["devices"]["192.168.100.2"]["interfaces"]["0"]["top_out_src_ips_packets"][0]["estimate"] == 1472);
}

TEST_CASE("Flow invalid config", "[flow][filter][config]")
{
    FlowInputStream stream{"netflow-test"};
    stream.config_set("flow_type", "netflow");
    stream.config_set("pcap_file", "tests/fixtures/nf9.pcap");

    visor::Config c;
    auto stream_proxy = stream.add_event_proxy(c);
    c.config_set<uint64_t>("num_periods", 1);
    FlowStreamHandler flow_handler{"flow-test", stream_proxy, &c};
    flow_handler.config_set<bool>("invalid_config", true);
    REQUIRE_THROWS_WITH(flow_handler.start(), "invalid_config is an invalid/unsupported config or filter. The valid configs/filters are: device_map, enrichment, only_device_interfaces, only_ips, only_ports, only_directions, geoloc_notfound, asn_notfound, summarize_ips_by_asn, subnets_for_summarization, exclude_asns_from_summarization, exclude_unknown_asns_from_summarization, exclude_ips_from_summarization, sample_rate_scaling, recorded_stream, deep_sample_rate, num_periods, topn_count, topn_percentile_threshold");
}