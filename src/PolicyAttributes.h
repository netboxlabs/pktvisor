/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#pragma once

#include "MetricLabels.h"
#include <map>
#include <set>
#include <string>
#include <vector>
#include <yaml-cpp/yaml.h>

namespace visor {

// The attributes of each netprobe target, by target name.
using TargetAttributes = std::map<std::string, LabelMap>;

// Reads the `attributes` mapping of a policy (`where` names it in errors). Values are the text
// as written in the YAML, so "007" stays 007 and "True" stays True. A null node is no attributes.
// Throws PolicyException for a node that is not a map, for a key that is empty, is not valid UTF-8 or
// does not start with an ASCII letter, and for a value that is not a scalar, is null or is empty.
LabelMap parse_attributes(const YAML::Node &node, const std::string &where);

// Reads the `attributes` of every target in input.config.targets of a policy's `input` node, each as
// parse_attributes does, from the YAML as written. Targets without attributes are left out, and the
// result is empty when there is no targets map.
TargetAttributes parse_target_attributes(const YAML::Node &input_node, const std::string &policy_name);

// A copy of a policy's `input` node with the `attributes` of every target in input.config.targets removed, the
// node the policy builds and names its input from. Target attributes belong to the policy, not to the input: kept
// out of its config, they are never read as typed config values, and policies that differ only in them share one
// input. `input_node` itself is left as it is, and one with no target attributes, or that is not a map,
// comes back as it is (a clone loses the positions that YAML errors report).
YAML::Node without_target_attributes(const YAML::Node &input_node);

// Throws PolicyException, naming `where` and the key, when the Prometheus name of an attribute key is in
// `reserved` (labels pktvisor sets itself, in their Prometheus form). A collision is refused, never resolved.
void check_reserved(const LabelMap &attrs, const std::set<std::string> &reserved, const std::string &where);

// The labels pktvisor sets itself on a policy's series, in their Prometheus form: those of every policy
// (policy, handler, tap, le, quantile), the static labels, and `handler_labels`, the own_label_names of
// the policy's handlers.
std::set<std::string> reserved_label_names(const std::vector<std::string> &handler_labels);

// Throws PolicyException, naming the policy, the target and the key, when a target's attributes would
// put on its series a label pktvisor sets itself (one in `reserved`), or a key written as the Prometheus
// label of a different key in the policy's own attributes: laid over those, both would reach the series
// under one label name. The same key, spelled the same, is an override and is allowed.
void check_target_attributes(const TargetAttributes &targets, const LabelMap &policy_attrs, const std::set<std::string> &reserved, const std::string &policy_name);

}
