/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#pragma once

#include "MetricLabels.h"
#include <set>
#include <string>
#include <yaml-cpp/yaml.h>

namespace visor {

// Reads the `attributes` mapping of a policy (`where` names it in errors). Values are the text
// as written in the YAML, so "007" stays 007 and "True" stays True. Throws PolicyException for
// a node that is not a map, and for a value that is not a scalar, is null or is empty.
LabelMap parse_attributes(const YAML::Node &node, const std::string &where);

// A Prometheus label name for an attribute key: every character outside [A-Za-z0-9_] becomes _.
std::string prometheus_label_name(const std::string &key);

// Throws PolicyException, naming `where` and the key, when the Prometheus name of an attribute key is in
// `reserved` (labels pktvisor sets itself, in their Prometheus form). A collision is refused, never resolved.
void check_reserved(const LabelMap &attrs, const std::set<std::string> &reserved, const std::string &where);

}
