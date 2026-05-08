/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#pragma once

#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace visor {

/**
 * In-process plugin registry. Plugins register themselves at static-init time
 * via the VISOR_REGISTER_*_PLUGIN macros, which append a factory + metadata
 * entry to the per-base-class singleton registry. CoreRegistry then iterates
 * each registry's entries to instantiate the static plugins.
 */
template <typename PluginBase>
class PluginRegistry
{
public:
    using Factory = std::function<std::unique_ptr<PluginBase>()>;

    struct Entry {
        std::string alias;
        std::string version;
        std::string interface;
        Factory factory;
    };

    static PluginRegistry &instance()
    {
        static PluginRegistry registry;
        return registry;
    }

    void add(Entry entry)
    {
        _entries.push_back(std::move(entry));
    }

    [[nodiscard]] const std::vector<Entry> &entries() const
    {
        return _entries;
    }

private:
    PluginRegistry() = default;
    std::vector<Entry> _entries;
};

template <typename PluginBase>
struct PluginRegistrar {
    explicit PluginRegistrar(typename PluginRegistry<PluginBase>::Entry entry)
    {
        PluginRegistry<PluginBase>::instance().add(std::move(entry));
    }
};

}

/* Each plugin .cpp invokes one of these macros at file scope. The static
 * registrar registers the plugin at static-init time. The exported integer
 * symbol is referenced from static_plugins.h to force the linker to keep
 * the .o when linking against the plugin's static archive.
 *
 * SYMBOL is a unique C-identifier token (e.g. VisorHandlerNet) used to name
 * the force-link extern and the registrar; CLASS is the fully-qualified C++
 * class name (with ::) used in std::make_unique. */
#define VISOR_REGISTER_HANDLER_PLUGIN(SYMBOL, CLASS, ALIAS, VERSION)                                        \
    extern "C" int visor_force_link_##SYMBOL = 1;                                                           \
    static const ::visor::PluginRegistrar<::visor::HandlerModulePlugin> _visor_registrar_##SYMBOL{          \
        {ALIAS, VERSION, ::visor::HandlerModulePlugin::pluginInterface(),                                   \
            []() -> std::unique_ptr<::visor::HandlerModulePlugin> { return std::make_unique<CLASS>(ALIAS); }}};

#define VISOR_REGISTER_INPUT_PLUGIN(SYMBOL, CLASS, ALIAS, VERSION)                                          \
    extern "C" int visor_force_link_##SYMBOL = 1;                                                           \
    static const ::visor::PluginRegistrar<::visor::InputModulePlugin> _visor_registrar_##SYMBOL{            \
        {ALIAS, VERSION, ::visor::InputModulePlugin::pluginInterface(),                                     \
            []() -> std::unique_ptr<::visor::InputModulePlugin> { return std::make_unique<CLASS>(ALIAS); }}};

/* For plugins that publish more than one alias (e.g. flow input also serves "sflow").
 * SYMBOL must be unique across all alias registrations. */
#define VISOR_REGISTER_INPUT_PLUGIN_ALIAS(SYMBOL, CLASS, ALIAS, VERSION)                                    \
    static const ::visor::PluginRegistrar<::visor::InputModulePlugin> _visor_registrar_##SYMBOL{            \
        {ALIAS, VERSION, ::visor::InputModulePlugin::pluginInterface(),                                     \
            []() -> std::unique_ptr<::visor::InputModulePlugin> { return std::make_unique<CLASS>(ALIAS); }}};
