/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#pragma once

#include "EndianPortable.h"
#include <netflow.h>
#include <robin_hood.h>
#include <vector>

namespace visor::input::flow {

struct NFSample {
    /* the raw pdu */
    uint8_t *raw_sample{nullptr};
    uint32_t raw_sample_len{0};

    /* common header */
    uint16_t version{0};
    uint16_t nflows{0};

    /* most common header */
    uint32_t uptime_ms{0};
    uint32_t time_sec{0};
    uint32_t time_nanosec{0};
    uint32_t flow_sequence{0};
    uint32_t source_id{0};

    struct Flows {
        bool is_ipv6 = false;
        std::array<uint8_t, 16> src_ip{}, dst_ip{}, nexthop_ip{};
        uint16_t if_index_in{0}, if_index_out{0};
        uint32_t flow_packets{0}, flow_octets{0};
        uint32_t flow_start{0}, flow_finish{0};
        uint16_t src_port{0}, dst_port{0};
        uint8_t protocol{0}, tos{0}, tcp_flags{0};
        uint16_t src_as{0}, dst_as{0};
        uint8_t src_mask{0}, dst_mask{0};
    };
    std::vector<Flows> flows;
};

// A hash function used to hash a pair of any kind
struct hash_pair {
    template <class T1, class T2>
    size_t operator()(const std::pair<T1, T2> &p) const
    {
        auto hash1 = std::hash<T1>{}(p.first);
        auto hash2 = std::hash<T2>{}(p.second);
        return hash1 ^ hash2;
    }
};

using NfMapID = std::pair<uint32_t, uint16_t>;
static robin_hood::unordered_node_map<NfMapID, peer_nf9_template, hash_pair> nf9_template_map;
static robin_hood::unordered_node_map<NfMapID, peer_nf10_template, hash_pair> nf10_template_map;

static bool process_netflow_v1(NFSample *sample)
{
    struct NF1_HEADER *nf1_hdr = reinterpret_cast<struct NF1_HEADER *>(sample->raw_sample);
    struct NF1_FLOW *nf1_flow;
    size_t offset;

    if (sample->raw_sample_len < sizeof(*nf1_hdr)) {
        return false;
    }

    if (sample->nflows == 0 || sample->nflows > NF1_MAXFLOWS || sample->raw_sample_len != NF1_PACKET_SIZE(sample->nflows)) {
        return false;
    }

    sample->uptime_ms = be32toh(nf1_hdr->uptime_ms);
    sample->time_sec = be32toh(nf1_hdr->time_sec);
    sample->time_nanosec = be32toh(nf1_hdr->time_nanosec);

    for (uint16_t flow = 0; flow < sample->nflows; flow++) {
        offset = NF1_PACKET_SIZE(flow);
        nf1_flow = reinterpret_cast<struct NF1_FLOW *>(sample->raw_sample + offset);
        NFSample::Flows flow_sample = {};

        flow_sample.tcp_flags = nf1_flow->tcp_flags;
        flow_sample.protocol = nf1_flow->protocol;
        flow_sample.tos = nf1_flow->tos;

        memcpy(flow_sample.src_ip.data(), &nf1_flow->src_ip, sizeof(uint32_t));
        memcpy(flow_sample.dst_ip.data(), &nf1_flow->dest_ip, sizeof(uint32_t));
        memcpy(flow_sample.nexthop_ip.data(), &nf1_flow->nexthop_ip, sizeof(uint32_t));

        flow_sample.src_port = be16toh(nf1_flow->src_port);
        flow_sample.dst_port = be16toh(nf1_flow->dest_port);

        flow_sample.flow_start = be32toh(nf1_flow->flow_start);
        flow_sample.flow_finish = be32toh(nf1_flow->flow_finish);

        flow_sample.if_index_in = be16toh(nf1_flow->if_index_in);
        flow_sample.if_index_out = be16toh(nf1_flow->if_index_out);
        flow_sample.flow_octets = be32toh(nf1_flow->flow_octets);
        flow_sample.flow_packets = be32toh(nf1_flow->flow_packets);

        sample->flows.push_back(flow_sample);
    }

    return true;
}

static bool process_netflow_v5(NFSample *sample)
{
    struct NF5_HEADER *nf5_hdr = reinterpret_cast<struct NF5_HEADER *>(sample->raw_sample);
    struct NF5_FLOW *nf5_flow;
    size_t offset;

    if (sample->raw_sample_len < sizeof(*nf5_hdr)) {
        return false;
    }

    if (sample->nflows == 0 || sample->nflows > NF5_MAXFLOWS || sample->raw_sample_len != NF5_PACKET_SIZE(sample->nflows)) {
        return false;
    }

    sample->uptime_ms = be32toh(nf5_hdr->uptime_ms);
    sample->time_sec = be32toh(nf5_hdr->time_sec);
    sample->time_nanosec = be32toh(nf5_hdr->time_nanosec);
    sample->flow_sequence = be32toh(nf5_hdr->flow_sequence);

    for (uint16_t flow = 0; flow < sample->nflows; flow++) {
        offset = NF5_PACKET_SIZE(flow);
        nf5_flow = reinterpret_cast<struct NF5_FLOW *>(sample->raw_sample + offset);
        NFSample::Flows flow_sample = {};

        flow_sample.tcp_flags = nf5_flow->tcp_flags;
        flow_sample.protocol = nf5_flow->protocol;
        flow_sample.tos = nf5_flow->tos;

        memcpy(flow_sample.src_ip.data(), &nf5_flow->src_ip, sizeof(uint32_t));
        memcpy(flow_sample.dst_ip.data(), &nf5_flow->dest_ip, sizeof(uint32_t));
        memcpy(flow_sample.nexthop_ip.data(), &nf5_flow->nexthop_ip, sizeof(uint32_t));

        flow_sample.src_port = be16toh(nf5_flow->src_port);
        flow_sample.dst_port = be16toh(nf5_flow->dest_port);

        flow_sample.flow_start = be32toh(nf5_flow->flow_start);
        flow_sample.flow_finish = be32toh(nf5_flow->flow_finish);

        flow_sample.if_index_in = be16toh(nf5_flow->if_index_in);
        flow_sample.if_index_out = be16toh(nf5_flow->if_index_out);
        flow_sample.flow_octets = be32toh(nf5_flow->flow_octets);
        flow_sample.flow_packets = be32toh(nf5_flow->flow_packets);

        flow_sample.src_as = be16toh(nf5_flow->src_as);
        flow_sample.dst_as = be16toh(nf5_flow->dest_as);
        flow_sample.src_mask = nf5_flow->src_mask;
        flow_sample.dst_mask = nf5_flow->dst_mask;

        sample->flows.push_back(flow_sample);
    }

    return true;
}

static bool process_netflow_v7(NFSample *sample)
{
    struct NF7_HEADER *nf7_hdr = reinterpret_cast<struct NF7_HEADER *>(sample->raw_sample);
    struct NF7_FLOW *nf7_flow;
    size_t offset;

    if (sample->raw_sample_len < sizeof(*nf7_hdr)) {
        return false;
    }

    if (sample->nflows == 0 || sample->nflows > NF7_MAXFLOWS || sample->raw_sample_len != NF7_PACKET_SIZE(sample->nflows)) {
        return false;
    }

    sample->uptime_ms = be32toh(nf7_hdr->uptime_ms);
    sample->time_sec = be32toh(nf7_hdr->time_sec);
    sample->time_nanosec = be32toh(nf7_hdr->time_nanosec);
    sample->flow_sequence = be32toh(nf7_hdr->flow_sequence);

    for (uint16_t flow = 0; flow < sample->nflows; flow++) {
        offset = NF7_PACKET_SIZE(flow);
        nf7_flow = reinterpret_cast<struct NF7_FLOW *>(sample->raw_sample + offset);
        NFSample::Flows flow_sample = {};

        flow_sample.tcp_flags = nf7_flow->tcp_flags;
        flow_sample.protocol = nf7_flow->protocol;
        flow_sample.tos = nf7_flow->tos;

        memcpy(flow_sample.src_ip.data(), &nf7_flow->src_ip, sizeof(uint32_t));
        memcpy(flow_sample.dst_ip.data(), &nf7_flow->dest_ip, sizeof(uint32_t));
        memcpy(flow_sample.nexthop_ip.data(), &nf7_flow->nexthop_ip, sizeof(uint32_t));

        flow_sample.src_port = be16toh(nf7_flow->src_port);
        flow_sample.dst_port = be16toh(nf7_flow->dest_port);

        flow_sample.flow_start = be32toh(nf7_flow->flow_start);
        flow_sample.flow_finish = be32toh(nf7_flow->flow_finish);

        flow_sample.if_index_in = be16toh(nf7_flow->if_index_in);
        flow_sample.if_index_out = be16toh(nf7_flow->if_index_out);
        flow_sample.flow_octets = be32toh(nf7_flow->flow_octets);
        flow_sample.flow_packets = be32toh(nf7_flow->flow_packets);

        flow_sample.src_as = be16toh(nf7_flow->src_as);
        flow_sample.dst_as = be16toh(nf7_flow->dest_as);
        flow_sample.src_mask = nf7_flow->src_mask;
        flow_sample.dst_mask = nf7_flow->dst_mask;

        sample->flows.push_back(flow_sample);
    }

    return true;
}

static inline void be_copy(uint8_t *data, uint8_t *target, uint32_t target_length, uint32_t rec_length)
{
    if (target_length < rec_length) {
        // truncate for known common types
        if (target_length == sizeof(uint16_t) && rec_length == sizeof(uint32_t)) {
            uint32_t value{0};
            memcpy(&value, data, rec_length);
            uint16_t truncated = static_cast<uint16_t>(value >> 16);
            memcpy(target, &truncated, target_length);
        } else if (target_length == sizeof(uint32_t) && rec_length == sizeof(uint64_t)) {
            uint64_t value{0};
            memcpy(&value, data, rec_length);
            uint32_t truncated = static_cast<uint32_t>(value >> 32);
            memcpy(target, &truncated, target_length);
        }
    } else {
        memcpy(target + (target_length - rec_length), data, rec_length);
    }
}

static bool process_netflow_v9_template(uint8_t *pkt, size_t len, uint32_t source_id)
{
    struct NF9_FLOWSET_HEADER_COMMON *template_header;
    struct NF9_TEMPLATE_FLOWSET_HEADER *tmplh;
    struct NF9_TEMPLATE_FLOWSET_RECORD *tmplr;
    uint16_t template_id;
    uint32_t i, count, offset, total_size;

    template_header = reinterpret_cast<struct NF9_FLOWSET_HEADER_COMMON *>(pkt);
    if (len < sizeof(*template_header)) {
        return false;
    }

    if (be16toh(template_header->flowset_id) != NF9_TEMPLATE_FLOWSET_ID) {
        return false;
    }

    for (offset = sizeof(*template_header); offset < len;) {
        tmplh = reinterpret_cast<struct NF9_TEMPLATE_FLOWSET_HEADER *>(pkt + offset);

        template_id = be16toh(tmplh->template_id);
        count = be16toh(tmplh->count);
        offset += sizeof(*tmplh);

        total_size = 0;
        std::vector<peer_nf9_record> template_recs;
        for (i = 0; i < count; i++) {
            if (offset >= len) {
                return false;
            }

            tmplr = reinterpret_cast<struct NF9_TEMPLATE_FLOWSET_RECORD *>(pkt + offset);
            uint32_t rec_length = be16toh(tmplr->length);

            peer_nf9_record recs(be16toh(tmplr->type), rec_length);
            offset += sizeof(*tmplr);
            template_recs.push_back(recs);
            total_size += rec_length;
        }

        nf9_template_map[NfMapID(source_id, template_id)] = {template_id, source_id, count, total_size, template_recs};
    }

    return true;
}

static void nf9_rec_to_flow(NFSample::Flows *flow, struct peer_nf9_record *rec, uint8_t *data)
{
    /* XXX: use a table-based interpreter */
    switch (rec->type) {

#define V9_FIELD(v9_field, target, target_length)                                    \
    case v9_field:                                                                   \
        be_copy(data, reinterpret_cast<uint8_t *>(target), target_length, rec->len); \
        break
#define V9_FIELD_16(v9_field, target, target_length)                                 \
    case v9_field:                                                                   \
        be_copy(data, reinterpret_cast<uint8_t *>(target), target_length, rec->len); \
        *(target) = be16toh(*target);                                                \
        break
#define V9_FIELD_32(v9_field, target, target_length)                                 \
    case v9_field:                                                                   \
        be_copy(data, reinterpret_cast<uint8_t *>(target), target_length, rec->len); \
        *(target) = be32toh(*target);                                                \
        break

        V9_FIELD_32(NF9_IN_BYTES, &flow->flow_octets, sizeof(flow->flow_octets));
        V9_FIELD_32(NF9_IN_PACKETS, &flow->flow_packets, sizeof(flow->flow_octets));
        V9_FIELD(NF9_IN_PROTOCOL, &flow->protocol, sizeof(flow->protocol));
        V9_FIELD(NF9_SRC_TOS, &flow->tos, sizeof(flow->tos));
        V9_FIELD(NF9_TCP_FLAGS, &flow->tcp_flags, sizeof(flow->tcp_flags));
        V9_FIELD(NF9_SRC_MASK, &flow->src_mask, sizeof(flow->src_mask));
        V9_FIELD(NF9_DST_MASK, &flow->dst_mask, sizeof(flow->dst_mask));
        V9_FIELD_16(NF9_L4_SRC_PORT, &flow->src_port, sizeof(flow->src_port));
        V9_FIELD_16(NF9_INPUT_SNMP, &flow->if_index_in, sizeof(flow->if_index_in));
        V9_FIELD_16(NF9_L4_DST_PORT, &flow->dst_port, sizeof(flow->dst_port));
        V9_FIELD_16(NF9_OUTPUT_SNMP, &flow->if_index_out, sizeof(flow->if_index_out));
        V9_FIELD_16(NF9_SRC_AS, &flow->src_as, sizeof(flow->src_as));
        V9_FIELD_16(NF9_DST_AS, &flow->dst_as, sizeof(flow->dst_as));
        V9_FIELD_32(NF9_LAST_SWITCHED, &flow->flow_finish, sizeof(flow->flow_finish));
        V9_FIELD_32(NF9_FIRST_SWITCHED, &flow->flow_start, sizeof(flow->flow_start));
        V9_FIELD(NF9_IPV6_SRC_MASK, &flow->src_mask, sizeof(flow->src_mask));
        V9_FIELD(NF9_IPV6_DST_MASK, &flow->dst_mask, sizeof(flow->dst_mask));
        V9_FIELD(NF9_IPV4_SRC_ADDR, &flow->src_ip, sizeof(uint32_t));
        V9_FIELD(NF9_IPV6_SRC_ADDR, &flow->src_ip, sizeof(flow->src_ip));
        V9_FIELD(NF9_IPV4_DST_ADDR, &flow->dst_ip, sizeof(uint32_t));
        V9_FIELD(NF9_IPV6_DST_ADDR, &flow->dst_ip, sizeof(flow->dst_ip));
        V9_FIELD(NF9_IPV4_NEXT_HOP, &flow->nexthop_ip, sizeof(uint32_t));
        V9_FIELD(NF9_IPV6_NEXT_HOP, &flow->nexthop_ip, sizeof(flow->nexthop_ip));

    case NF9_IP_PROTOCOL_VERSION:
        if (*data == 6) {
            flow->is_ipv6 = true;
        }
        break;
#undef V9_FIELD_32
#undef V9_FIELD_16
#undef V9_FIELD
    }
}

static bool process_netflow_v9_data(std::vector<NFSample::Flows> *flows, uint8_t *pkt, size_t len, uint32_t source_id, uint32_t &num_flows)
{
    struct NF9_DATA_FLOWSET_HEADER *dath;
    uint16_t flowset_id, offset, num_flowsets;

    if (nf9_template_map.empty()) {
        return false;
    }

    num_flows = 0;

    dath = reinterpret_cast<struct NF9_DATA_FLOWSET_HEADER *>(pkt);
    if (len < sizeof(*dath)) {
        return false;
    }

    flowset_id = be16toh(dath->c.flowset_id);

    auto iter = nf9_template_map.find(NfMapID(source_id, flowset_id));
    if (iter == nf9_template_map.end()) {
        return false;
    }

    auto nf9_template = iter->second;
    if (nf9_template.records.empty()) {
        return false;
    }

    offset = sizeof(*dath);
    num_flowsets = (len - offset) / nf9_template.total_len;

    if (num_flowsets == 0 || num_flowsets > 0x4000) {
        return false;
    }

    uint32_t j = 0;
    for (uint16_t i = 0; i < num_flowsets; i++) {
        uint32_t offset_recs = 0;
        NFSample::Flows flow = {};
        for (j = 0; j < nf9_template.num_records; j++) {
            nf9_rec_to_flow(&flow, &nf9_template.records[j], pkt + offset + offset_recs);
            offset_recs += nf9_template.records[j].len;
        }
        flows->push_back(flow);
        offset += nf9_template.total_len;
    }
    num_flows = j;
    return true;
}

static bool process_netflow_v9(NFSample *sample)
{
    struct NF9_HEADER *nf9_hdr = reinterpret_cast<struct NF9_HEADER *>(sample->raw_sample);

    if (sample->raw_sample_len < sizeof(*nf9_hdr)) {
        return false;
    }

    struct NF9_FLOWSET_HEADER_COMMON *flowset;
    uint32_t i, flowset_id, flowset_len, flowset_flows;
    uint32_t offset, total_flows;

    sample->uptime_ms = be32toh(nf9_hdr->uptime_ms);
    sample->time_sec = be32toh(nf9_hdr->time_sec);
    sample->flow_sequence = be32toh(nf9_hdr->package_sequence);
    sample->source_id = be32toh(nf9_hdr->source_id);

    offset = sizeof(*nf9_hdr);
    total_flows = 0;

    std::vector<NFSample::Flows> flows;
    for (i = 0;; i++) {
        /* Make sure we don't run off the end of the flow */
        if (offset >= sample->raw_sample_len) {
            break;
        }

        flowset = reinterpret_cast<struct NF9_FLOWSET_HEADER_COMMON *>(sample->raw_sample + offset);
        flowset_id = be16toh(flowset->flowset_id);
        flowset_len = be16toh(flowset->length);

        /* Make sure we don't run off the end of the flow */
        if (offset + flowset_len > sample->raw_sample_len) {
            break;
        }

        switch (flowset_id) {
        case NF9_TEMPLATE_FLOWSET_ID:
            if (!process_netflow_v9_template(sample->raw_sample + offset, flowset_len, sample->source_id)) {
                return false;
            }
            break;
        case NF9_OPTIONS_FLOWSET_ID:
            /* XXX: implement this (maybe) */
            break;
        default:
            if (flowset_id < NF9_MIN_RECORD_FLOWSET_ID) {
                /* XXX ratelimit */
                break;
            }
            if (!process_netflow_v9_data(&flows, sample->raw_sample + offset, flowset_len, sample->source_id, flowset_flows)) {
                return false;
            }
            total_flows += flowset_flows;
            break;
        }
        offset += flowset_len;
        if (offset == sample->raw_sample_len)
            break;
        /* XXX check header->count against what we got */
    }

    sample->flows = flows;

    if (total_flows > 0) {
        return true;
    }
    return false;
}

static void nf10_rec_to_flow(NFSample::Flows *flow, struct peer_nf10_record *rec, uint8_t *data)
{
    /* XXX: use a table-based interpreter */
    switch (rec->type) {

#define V10_FIELD(v10_field, target, target_length)                                  \
    case v10_field:                                                                  \
        be_copy(data, reinterpret_cast<uint8_t *>(target), target_length, rec->len); \
        break
#define V10_FIELD_16(v10_field, target, target_length)                               \
    case v10_field:                                                                  \
        be_copy(data, reinterpret_cast<uint8_t *>(target), target_length, rec->len); \
        *(target) = be16toh(*target);                                                \
        break
#define V10_FIELD_32(v10_field, target, target_length)                               \
    case v10_field:                                                                  \
        be_copy(data, reinterpret_cast<uint8_t *>(target), target_length, rec->len); \
        *(target) = be32toh(*target);                                                \
        break

        V10_FIELD_32(NF10_IN_BYTES, &flow->flow_octets, sizeof(flow->flow_octets));
        V10_FIELD_32(NF10_IN_PACKETS, &flow->flow_packets, sizeof(flow->flow_octets));
        V10_FIELD(NF10_IN_PROTOCOL, &flow->protocol, sizeof(flow->protocol));
        V10_FIELD(NF10_SRC_TOS, &flow->tos, sizeof(flow->tos));
        V10_FIELD(NF10_TCP_FLAGS, &flow->tcp_flags, sizeof(flow->tcp_flags));
        V10_FIELD(NF10_SRC_MASK, &flow->src_mask, sizeof(flow->src_mask));
        V10_FIELD(NF10_DST_MASK, &flow->dst_mask, sizeof(flow->dst_mask));
        V10_FIELD_16(NF10_L4_SRC_PORT, &flow->src_port, sizeof(flow->src_port));
        V10_FIELD_16(NF10_INPUT_SNMP, &flow->if_index_in, sizeof(flow->if_index_in));
        V10_FIELD_16(NF10_L4_DST_PORT, &flow->dst_port, sizeof(flow->dst_port));
        V10_FIELD_16(NF10_OUTPUT_SNMP, &flow->if_index_out, sizeof(flow->if_index_out));
        V10_FIELD_16(NF10_SRC_AS, &flow->src_as, sizeof(flow->src_as));
        V10_FIELD_16(NF10_DST_AS, &flow->dst_as, sizeof(flow->dst_as));
        V10_FIELD_32(NF10_LAST_SWITCHED, &flow->flow_finish, sizeof(flow->flow_finish));
        V10_FIELD_32(NF10_FIRST_SWITCHED, &flow->flow_start, sizeof(flow->flow_start));
        V10_FIELD(NF10_IPV6_SRC_MASK, &flow->src_mask, sizeof(flow->src_mask));
        V10_FIELD(NF10_IPV6_DST_MASK, &flow->dst_mask, sizeof(flow->dst_mask));
        V10_FIELD(NF10_IPV4_SRC_ADDR, &flow->src_ip, sizeof(uint32_t));
        V10_FIELD(NF10_IPV6_SRC_ADDR, &flow->src_ip, sizeof(flow->src_ip));
        V10_FIELD(NF10_IPV4_DST_ADDR, &flow->dst_ip, sizeof(uint32_t));
        V10_FIELD(NF10_IPV6_DST_ADDR, &flow->dst_ip, sizeof(flow->dst_ip));
        V10_FIELD(NF10_IPV4_NEXT_HOP, &flow->nexthop_ip, sizeof(uint32_t));
        V10_FIELD(NF10_IPV6_NEXT_HOP, &flow->nexthop_ip, sizeof(flow->nexthop_ip));

    case NF10_IP_PROTOCOL_VERSION:
        if (*data == 6) {
            flow->is_ipv6 = true;
        }
        break;
#undef V10_FIELD_32
#undef V10_FIELD_16
#undef V10_FIELD
    }
}

static bool process_netflow_v10_data(std::vector<NFSample::Flows> *flows, uint8_t *pkt, size_t len, uint32_t source_id, uint32_t &num_flows)
{
    struct NF10_DATA_FLOWSET_HEADER *dath;
    uint16_t flowset_id, offset, num_flowsets;

    if (nf10_template_map.empty()) {
        return false;
    }

    num_flows = 0;

    dath = reinterpret_cast<struct NF10_DATA_FLOWSET_HEADER *>(pkt);
    if (len < sizeof(*dath)) {
        return false;
    }

    flowset_id = be16toh(dath->c.flowset_id);
    auto iter = nf10_template_map.find(NfMapID(source_id, flowset_id));
    if (iter == nf10_template_map.end()) {
        return false;
    }

    auto nf10_template = iter->second;
    if (nf10_template.records.empty()) {
        return false;
    }

    offset = sizeof(*dath);
    num_flowsets = (len - offset) / nf10_template.total_len;

    if (num_flowsets == 0 || num_flowsets > 0x4000) {
        return false;
    }

    uint32_t j = 0;
    for (uint16_t i = 0; i < num_flowsets; i++) {
        uint32_t offset_recs = 0;
        NFSample::Flows flow = {};
        for (j = 0; j < nf10_template.num_records; j++) {
            nf10_rec_to_flow(&flow, &nf10_template.records[j], pkt + offset + offset_recs);
            // i.e. if variable size, first byte contains the size
            (nf10_template.records[j].len == 0xFFFF) ? offset_recs += (*(pkt + offset + offset_recs) + 1) : offset_recs += nf10_template.records[j].len;
        }
        flows->push_back(flow);
        offset += nf10_template.total_len;
    }
    num_flows = j;
    return true;
}

static bool process_netflow_v10_template(uint8_t *pkt, size_t len, uint32_t source_id)
{
    struct NF10_FLOWSET_HEADER_COMMON *template_header;
    struct NF10_TEMPLATE_FLOWSET_HEADER *tmplh;
    struct NF10_TEMPLATE_FLOWSET_RECORD *tmplr;
    uint16_t template_id;
    uint32_t i, count, offset, total_size;

    template_header = reinterpret_cast<struct NF10_FLOWSET_HEADER_COMMON *>(pkt);
    if (len < sizeof(*template_header)) {
        return false;
    }

    if (be16toh(template_header->flowset_id) != NF10_TEMPLATE_FLOWSET_ID) {
        return false;
    }

    for (offset = sizeof(*template_header); offset < len;) {
        tmplh = reinterpret_cast<struct NF10_TEMPLATE_FLOWSET_HEADER *>(pkt + offset);

        template_id = be16toh(tmplh->template_id);
        count = be16toh(tmplh->count);
        offset += sizeof(*tmplh);

        total_size = 0;
        std::vector<peer_nf10_record> template_recs;
        for (i = 0; i < count; i++) {
            if (offset >= len) {
                return false;
            }

            tmplr = reinterpret_cast<struct NF10_TEMPLATE_FLOWSET_RECORD *>(pkt + offset);
            uint32_t rec_type = be16toh(tmplr->type);
            uint32_t rec_length = be16toh(tmplr->length);

            peer_nf10_record recs(rec_type, rec_length);
            offset += sizeof(*tmplr);
            (rec_type & NF10_ENTERPRISE) ? offset += sizeof(uint32_t) : offset;
            template_recs.push_back(recs);
            (rec_length == 0xFFFF) ? total_size++ : total_size += rec_length; // i.e. variable length
        }

        nf10_template_map[NfMapID(source_id, template_id)] = {template_id, source_id, count, total_size, template_recs};
    }

    return true;
}

static bool process_netflow_v10(NFSample *sample)
{
    struct NF10_HEADER *nf10_hdr = reinterpret_cast<struct NF10_HEADER *>(sample->raw_sample);

    if (sample->raw_sample_len < sizeof(*nf10_hdr)) {
        return false;
    }

    struct NF10_FLOWSET_HEADER_COMMON *flowset;
    uint32_t i, flowset_id, flowset_len, flowset_flows;
    uint32_t offset, total_flows;

    sample->time_sec = be32toh(nf10_hdr->time_sec);
    sample->flow_sequence = be32toh(nf10_hdr->package_sequence);
    sample->source_id = be32toh(nf10_hdr->source_id);

    offset = sizeof(*nf10_hdr);
    total_flows = 0;

    std::vector<NFSample::Flows> flows;
    for (i = 0;; i++) {
        /* Make sure we don't run off the end of the flow */
        if (offset >= sample->raw_sample_len) {
            break;
        }

        flowset = reinterpret_cast<struct NF10_FLOWSET_HEADER_COMMON *>(sample->raw_sample + offset);
        flowset_id = be16toh(flowset->flowset_id);
        flowset_len = be16toh(flowset->length);

        /* Make sure we don't run off the end of the flow */
        if (offset + flowset_len > sample->raw_sample_len) {
            break;
        }

        switch (flowset_id) {
        case NF10_TEMPLATE_FLOWSET_ID:
            if (!process_netflow_v10_template(sample->raw_sample + offset, flowset_len, sample->source_id)) {
                return false;
            }
            break;
        case NF10_OPTIONS_FLOWSET_ID:
            /* XXX: implement this (maybe) */
            break;
        default:
            if (flowset_id < NF10_MIN_RECORD_FLOWSET_ID) {
                /* XXX ratelimit */
                break;
            }
            if (!process_netflow_v10_data(&flows, sample->raw_sample + offset, flowset_len, sample->source_id, flowset_flows)) {
                return false;
            }
            total_flows += flowset_flows;
            break;
        }
        offset += flowset_len;
        if (offset == sample->raw_sample_len)
            break;
        /* XXX check header->count against what we got */
    }

    sample->flows = flows;

    if (total_flows > 0) {
        return true;
    }
    return false;
}

static bool process_netflow_packet(NFSample *sample)
{
    struct NF_HEADER_COMMON *hdr = reinterpret_cast<struct NF_HEADER_COMMON *>(sample->raw_sample);

    sample->version = be16toh(hdr->version);
    sample->nflows = be16toh(hdr->flows);

    switch (sample->version) {
    case 1:
        return process_netflow_v1(sample);
    case 5:
        return process_netflow_v5(sample);
    case 7:
        return process_netflow_v7(sample);
    case 9:
        return process_netflow_v9(sample);
    case 10:
        return process_netflow_v10(sample);
    default:
        return false;
    }
}
}