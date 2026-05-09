/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#pragma once

namespace visor {

class CoreRegistry;

/**
 * Construct each built-in plugin and hand it to the registry via
 * add_input_plugin / add_handler_plugin. Call this once before
 * registry.start(). Defined in the visor-builtin-plugins static lib,
 * which is the only translation unit that pulls in plugin headers.
 */
void load_builtin_plugins(CoreRegistry &registry);

}
