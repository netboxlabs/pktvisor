/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "PolicyAttributes.h"
#include "Policies.h"
#include <fmt/format.h>
#include <map>
#include <optional>

namespace visor {

LabelMap parse_attributes(const YAML::Node &node, const std::string &where)
{
    if (!node.IsMap()) {
        throw PolicyException(fmt::format("attributes of {} is not a map", where));
    }
    LabelMap attrs;
    std::map<std::string, std::string> written_as; // Prometheus name -> key
    for (const auto &kv : node) {
        if (!kv.first.IsScalar()) {
            throw PolicyException(fmt::format("attributes of {} has a key that is not a scalar", where));
        }
        const auto key = kv.first.Scalar();
        if (!kv.second.IsScalar()) {
            throw PolicyException(fmt::format("attribute '{}' of {} must be a scalar value", key, where));
        }
        const auto &value = kv.second.Scalar();
        if (value.empty()) {
            throw PolicyException(fmt::format("attribute '{}' of {} must not be empty", key, where));
        }
        auto [seen, added] = written_as.emplace(prometheus_label_name(key), key);
        if (!added) {
            throw PolicyException(fmt::format("attributes '{}' and '{}' of {} are both written as the Prometheus label '{}'", seen->second, key, where, seen->first));
        }
        attrs[key] = value;
    }
    return attrs;
}

std::string prometheus_label_name(const std::string &key)
{
    std::string name(key);
    for (auto &c : name) {
        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_')) {
            c = '_';
        }
    }
    return name;
}

void check_reserved(const LabelMap &attrs, const std::set<std::string> &reserved, const std::string &where)
{
    for (const auto &[key, value] : attrs) {
        auto name = prometheus_label_name(key);
        if (reserved.count(name)) {
            throw PolicyException(fmt::format("attribute '{}' of {} collides with the label '{}' that pktvisor sets itself", key, where, name));
        }
    }
}

namespace {

// input.config.targets of a policy's input node, when it is a map. Each level is checked before it is indexed:
// yaml-cpp throws on a type check of a key that is not there.
std::optional<YAML::Node> targets_map(const YAML::Node &input_node)
{
    if (!input_node || !input_node.IsMap()) {
        return std::nullopt;
    }
    const auto config = input_node["config"];
    if (!config || !config.IsMap()) {
        return std::nullopt;
    }
    const auto targets = config["targets"];
    if (!targets || !targets.IsMap()) {
        return std::nullopt;
    }
    return targets;
}

}

TargetAttributes parse_target_attributes(const YAML::Node &input_node, const std::string &policy_name)
{
    TargetAttributes targets;
    auto config_targets = targets_map(input_node);
    if (!config_targets) {
        return targets;
    }
    for (const auto &kv : *config_targets) {
        // a target that is not a map of its own is the input's to refuse
        if (!kv.first.IsScalar() || !kv.second.IsMap() || !kv.second["attributes"]) {
            continue;
        }
        const auto &name = kv.first.Scalar();
        targets[name] = parse_attributes(kv.second["attributes"], fmt::format("policy '{}' target '{}'", policy_name, name));
    }
    return targets;
}

YAML::Node without_target_attributes(const YAML::Node &input_node)
{
    // a missing or malformed input is for the input manager to refuse, exactly as written
    if (!input_node || !input_node.IsMap()) {
        return input_node;
    }
    auto cleaned = YAML::Clone(input_node);
    if (auto config_targets = targets_map(cleaned)) {
        for (auto kv : *config_targets) {
            if (kv.second.IsMap()) {
                kv.second.remove("attributes");
            }
        }
    }
    return cleaned;
}

std::set<std::string> reserved_label_names(const std::vector<std::string> &handler_labels)
{
    std::set<std::string> reserved{"policy", "handler", "tap", "le", "quantile"};
    for (const auto &[label, value] : prometheus_static_labels()) {
        reserved.insert(prometheus_label_name(label));
    }
    for (const auto &label : handler_labels) {
        reserved.insert(prometheus_label_name(label));
    }
    return reserved;
}

void check_target_attributes(const TargetAttributes &targets, const LabelMap &policy_attrs, const std::set<std::string> &reserved, const std::string &policy_name)
{
    std::map<std::string, std::string> policy_keys; // Prometheus name -> key; parse_attributes keeps them one to one
    for (const auto &[key, value] : policy_attrs) {
        policy_keys.emplace(prometheus_label_name(key), key);
    }
    for (const auto &[target, attrs] : targets) {
        auto where = fmt::format("policy '{}' target '{}'", policy_name, target);
        check_reserved(attrs, reserved, where);
        for (const auto &[key, value] : attrs) {
            auto name = prometheus_label_name(key);
            auto found = policy_keys.find(name);
            if (found != policy_keys.end() && found->second != key) {
                throw PolicyException(fmt::format("attribute '{}' of {} and attribute '{}' of policy '{}' are both written as the Prometheus label '{}'", key, where, found->second, policy_name, name));
            }
        }
    }
}

}
