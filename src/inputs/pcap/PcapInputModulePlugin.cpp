/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "PcapInputModulePlugin.h"
#include "CoreRegistry.h"
#include "InputStreamManager.h"
namespace visor::input::pcap {

void PcapInputModulePlugin::setup_routes([[maybe_unused]] HttpServer *svr)
{
    // GET
    // svr->Get("/api/v1/inputs/pcap/(\\w+)", std::bind(&PcapInputModulePlugin::_read, this, std::placeholders::_1, std::placeholders::_2));
}

/*
void PcapInputModulePlugin::_read(const httplib::Request &req, httplib::Response &res)
{
    json result;
    try {
        auto name = req.matches[1];
        if (!registry()->input_manager()->module_exists(name)) {
            res.status = 404;
            result["error"] = "input name does not exist";
            res.set_content(result.dump(), "text/json");
            return;
        }
        auto [input_stream, stream_mgr_lock] = registry()->input_manager()->module_get_locked(name);
        assert(input_stream);
        input_stream->info_json(result);
        res.set_content(result.dump(), "text/json");
    } catch (const std::exception &e) {
        res.status = 500;
        result["error"] = e.what();
        res.set_content(result.dump(), "text/json");
    }
}
*/

std::unique_ptr<InputStream> PcapInputModulePlugin::instantiate(const std::string name, const Configurable *config, const Configurable *filter)
{
    auto input_stream = std::make_unique<PcapInputStream>(name);
    input_stream->config_merge(*config);
    input_stream->config_merge(*filter);
    return input_stream;
}

std::string PcapInputModulePlugin::generate_input_name(std::string prefix, const Configurable &config, const Configurable &filter)
{
    auto input_name(config);
    input_name.config_merge(filter);
    return prefix + "-" + input_name.config_hash();
}

}

namespace visor {
std::unique_ptr<InputModulePlugin> make_input_pcap(std::string alias)
{
    return std::make_unique<visor::input::pcap::PcapInputModulePlugin>(std::move(alias));
}
}
