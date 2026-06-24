/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */
#pragma once

#include <map>
#include <string>

namespace visor {

using LabelMap = std::map<std::string, std::string>;

// Process-global static labels (e.g. instance). Storage defined in Metrics.cpp.
LabelMap &prometheus_static_labels_mutable();
inline const LabelMap &prometheus_static_labels() { return prometheus_static_labels_mutable(); }

}
