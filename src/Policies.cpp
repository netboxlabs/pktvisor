/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "Policies.h"
#include "CoreRegistry.h"
#include "HandlerManager.h"
#include "InputStreamManager.h"
#include "PrometheusSerializer.h"
#include "Taps.h"
#include <algorithm>
#include <fmt/format.h>
#include <spdlog/spdlog.h>
#include <spdlog/stopwatch.h>

namespace visor {

std::vector<Policy *> PolicyManager::load_from_str(const std::string &str)
{
    if (str.empty()) {
        throw PolicyException("empty data");
    }

    YAML::Node node = YAML::Load(str);

    if (!node.IsMap() || !node["visor"]) {
        throw PolicyException("invalid schema");
    }
    if (!node["version"]) {
        spdlog::get("visor")->info("missing version, using version \"1.0\"");
    } else if (!node["version"].IsScalar() || node["version"].as<std::string>() != "1.0") {
        throw PolicyException("unsupported version");
    }
    if (node["visor"]["policies"] && node["visor"]["policies"].IsMap()) {
        return load(node["visor"]["policies"], true);
    } else {
        throw PolicyException("no policies found in schema");
    }
}

// needs to be thread safe and transactional: any errors mean resources get cleaned up with no side effects
std::vector<Policy *> PolicyManager::load(const YAML::Node &policy_yaml, bool single)
{
    assert(policy_yaml.IsMap());
    assert(spdlog::get("visor"));

    if (single && policy_yaml.size() > 1) {
        throw PolicyException(fmt::format("only a single policy expected but got {}", policy_yaml.size()));
    }

    std::vector<Policy *> result;
    for (YAML::const_iterator it = policy_yaml.begin(); it != policy_yaml.end(); ++it) {

        // serialized policy loads
        std::unique_lock lock(_load_mutex);

        auto policy_name = _get_policy_name(it);
        // Input Section
        auto input_node = it->second["input"];
        auto [input_config, input_filter] = _registry->input_manager()->get_config_and_filter(input_node);
        // Handler Default Section
        auto handler_node = it->second["handlers"];
        auto [window_config, handler_sequence] = _registry->handler_manager()->get_default_configuration(handler_node);

        // tap manager ensures that at least one tap is returned, if not it throws
        auto taps_name = _registry->tap_manager()->get_input_taps_name(input_node);

        // create policy
        auto policy = std::make_unique<Policy>(policy_name);
        auto policy_ptr = policy.get();
        policy_ptr->set_modules_sequence(handler_sequence);

        if (it->second["config"]) {
            if (!it->second["config"].IsMap()) {
                throw PolicyException("policy configuration is not a map");
            }
            try {
                policy_ptr->config_set_yaml(it->second["config"]);
            } catch (ConfigException &e) {
                throw HandlerException(fmt::format("invalid policy config for policy '{}': {}", policy_name, e.what()));
            }
        }

        std::vector<std::string> added_inputs;
        std::vector<std::string> added_handlers;
        // by name, like the resources policies below: once the policy is detached from an input, nothing keeps
        // that input alive, and a concurrent removal of its last policy can free it while this load runs
        std::vector<std::string> attached_inputs;
        std::vector<std::unique_ptr<Policy>> resources_policies;
        // by name: once registered, a resources policy can be deleted through the API while this load runs
        std::vector<std::string> added_resources_policies;
        // Undo everything this load did, one step at a time, so that a step that fails neither skips the rest
        // nor replaces the exception that started the rollback. stop() undoes a completed start; after a
        // partial one, Policy::start has already stopped the handlers, and the input manager stops the inputs
        // it removes. The policy is detached from the inputs it was attached to: a reused input outlives this
        // load and must not keep counting it, and an input it reached but never joined is left alone.
        auto rollback = [&]() {
            auto step = [&policy_name](auto &&undo) {
                try {
                    undo();
                } catch (const std::exception &e) {
                    spdlog::get("visor")->warn("policy [{}]: rollback: {}", policy_name, e.what());
                }
            };
            step([&] { policy_ptr->stop(); });
            for (auto &name : attached_inputs) {
                step([&] {
                    // under the policy map lock, as remove_policy does: no other removal can free the input
                    // meanwhile. one that is already gone was freed after stop() detached the policy
                    std::unique_lock policies_lock(_map_mutex);
                    InputStream *input = nullptr;
                    {
                        auto [inputs, inputs_lock] = _registry->input_manager()->module_get_all_locked();
                        auto found = inputs.find(name);
                        if (found == inputs.end()) {
                            return;
                        }
                        input = found->second.get();
                    }
                    input->remove_policy(policy_ptr);
                    // a reused input outlives this load. If its last other policy was removed while this one
                    // still counted on it, that removal left it running, so finish the teardown here
                    if (std::find(added_inputs.begin(), added_inputs.end(), name) == added_inputs.end()) {
                        _remove_input_if_unused(name, input, policy_name);
                    }
                });
            }
            for (auto &name : added_resources_policies) {
                step([&] {
                    auto [resources_policy, lock] = module_get_locked(name);
                    resources_policy->stop();
                });
                // unregistered even if it did not stop, since its input is removed below
                step([&] { module_remove(name); });
            }
            for (auto &m : added_handlers) {
                step([&] { _registry->handler_manager()->module_remove(m); });
            }
            for (auto &p : added_inputs) {
                step([&] { _registry->input_manager()->module_remove(p); });
            }
        };
        try {
            for (const auto &tap_name : taps_name) {
                auto [tap, tap_lock] = _registry->tap_manager()->module_get_locked(tap_name);
                policy_ptr->add_tap(tap);
                // ensure tap input type matches policy input tap
                if (input_node["input_type"].as<std::string>() != tap->input_plugin()->plugin()) {
                    throw PolicyException(fmt::format("input_type for policy specified tap '{}' doesn't match tap's defined input type: {}/{}", tap_name, input_node["input_type"].as<std::string>(), tap->input_plugin()->plugin()));
                }
                // handler internal config
                window_config.config_set<std::string>("_internal_tap_name", tap_name);

                std::string input_stream_name = tap->get_input_name(input_config, input_filter);
                if (!_registry->input_manager()->module_exists(input_stream_name)) {
                    try {
                        spdlog::get("visor")->info("policy [{}]: creating input stream: {}", policy_name, input_stream_name);
                        _registry->input_manager()->module_add(tap->instantiate(&input_config, &input_filter, input_stream_name));
                        added_inputs.push_back(input_stream_name);
                    } catch (std::runtime_error &e) {
                        throw PolicyException(fmt::format("unable to instantiate tap '{}': {}", tap_name, e.what()));
                    }
                } else {
                    spdlog::get("visor")->debug("policy [{}]: input stream already exists. reusing: {}", policy_name, input_stream_name);
                }

                auto [input_ptr, input_lock] = _registry->input_manager()->module_get_locked(input_stream_name);
                InputEventProxy *input_event_proxy = input_ptr->add_event_proxy(input_filter);
                policy_ptr->add_input_stream(input_ptr);

                std::vector<std::unique_ptr<StreamHandler>> handler_modules;
                for (YAML::const_iterator h_it = handler_node["modules"].begin(); h_it != handler_node["modules"].end(); ++h_it) {
                    auto handler_config = _registry->handler_manager()->validate_handler(h_it, policy_name, window_config, handler_sequence);
                    std::unique_ptr<StreamHandler> handler_module;
                    auto handler_plugin = _registry->handler_plugins().find(std::make_pair(handler_config.type, handler_config.version));
                    auto handler_name = policy_name + "-" + tap_name + "-" + handler_config.name;
                    if (!handler_sequence || handler_modules.empty()) {
                        handler_module = handler_plugin->second->instantiate(handler_name, input_event_proxy, &handler_config.config, &handler_config.filter);
                    } else {
                        // for sequence, use only previous handler
                        handler_modules.back()->set_event_proxy(input_ptr->create_event_proxy(Configurable()));
                        handler_module = handler_plugin->second->instantiate(handler_name, handler_modules.back()->get_event_proxy(), &handler_config.config, &handler_config.filter);
                    }
                    handler_module->set_version(handler_config.version);
                    policy_ptr->add_module(handler_module.get());
                    handler_modules.emplace_back(std::move(handler_module));
                }

                for (auto &m : handler_modules) {
                    auto hname = m->name();
                    _registry->handler_manager()->module_add(std::move(m));
                    added_handlers.push_back(hname);
                }

                // success
                input_ptr->add_policy(policy_ptr);
                attached_inputs.push_back(input_stream_name);
            }

        } catch (...) {
            // failed to create policy
            rollback();
            throw;
        }

        try {
            // every handler on a new input must be running before the input starts: an input that reads all
            // its data as it starts, such as a pcap_file or dnstap_file, is consumed by whichever policy starts
            // it. So start the resources handlers, then this policy (its handlers, then its inputs), and only
            // then the resources policies, whose handlers and inputs are already running.
            for (auto &p : added_inputs) {
                auto [input_ptr, input_lock] = _registry->input_manager()->module_get_locked(p);
                auto [resources_policy, module_name] = create_resources_policy(input_ptr, window_config);
                if (resources_policy) {
                    added_handlers.push_back(module_name);
                    resources_policies.push_back(std::move(resources_policy));
                }
            }
            policy_ptr->start();
            for (auto &resources_policy : resources_policies) {
                // attached before it is registered, and not touched after: from then on the API can delete it
                auto resources_name = resources_policy->name();
                resources_policy->start();
                resources_policy->input_stream().back()->add_policy(resources_policy.get());
                try {
                    module_add(std::move(resources_policy));
                } catch (...) {
                    // not registered, so still ours: stopping it also detaches it from its input
                    resources_policy->stop();
                    throw;
                }
                added_resources_policies.push_back(resources_name);
            }
            module_add(std::move(policy));
        } catch (const std::runtime_error &e) {
            rollback();
            throw PolicyException(fmt::format("policy [{}] failed to start: {}", policy_name, e.what()));
        } catch (...) {
            // anything else, such as a std::invalid_argument, is rethrown as it was so callers still tell it apart
            rollback();
            throw;
        }

        result.push_back(policy_ptr);
    }

    return result;
}

std::pair<std::unique_ptr<Policy>, std::string> PolicyManager::create_resources_policy(InputStream *input, const Config &window_config)
{
    auto resources_handler_plugin = _registry->handler_plugins().find(std::make_pair("input_resources", CoreRegistry::DEFAULT_HANDLER_PLUGIN_VERSION));
    if (resources_handler_plugin == _registry->handler_plugins().end()) {
        spdlog::get("visor")->info("input_resources handler not available, not able to create input resources policy for input stream: {}", input->name());
        return std::make_pair(nullptr, std::string());
    }

    // create new policy with resources handler for input stream. the handler is started and registered here;
    // the caller starts and registers the policy once the input is running
    auto resources_policy = std::make_unique<Policy>(input->name() + "-resources");
    resources_policy->add_input_stream(input);

    auto resources_module = resources_handler_plugin->second->instantiate(input->name() + "-resources", input->add_event_proxy(Configurable()), &window_config, nullptr);
    auto module_name = resources_module->name();
    resources_policy->add_module(resources_module.get());

    resources_module->start();
    try {
        _registry->handler_manager()->module_add(std::move(resources_module));
    } catch (const std::runtime_error &) {
        resources_module->stop();
        throw;
    }

    return std::make_pair(std::move(resources_policy), module_name);
}

std::string PolicyManager::_get_policy_name(YAML::const_iterator it)
{
    // Basic Structure
    if (!it->first.IsScalar()) {
        throw PolicyException("expecting policy identifier");
    }
    auto policy_name = it->first.as<std::string>();
    spdlog::get("visor")->info("policy [{}]: parsing", policy_name);
    if (!it->second.IsMap()) {
        throw PolicyException("expecting policy configuration map");
    }
    // Ensure policy name isn't already defined
    if (module_exists(policy_name)) {
        throw PolicyException(fmt::format("policy with name '{}' already defined", policy_name));
    }

    // Policy kind defines schema
    if (!it->second["kind"] || !it->second["kind"].IsScalar()) {
        throw PolicyException("missing or invalid policy kind at key 'kind'");
    }
    if (it->second["kind"].as<std::string>() != "collection") {
        throw PolicyException(fmt::format("unknown policy kind: {}", it->second["kind"].as<std::string>()));
    }
    return policy_name;
}

void PolicyManager::remove_policy(const std::string &name)
{
    std::unique_lock lock(_map_mutex);
    if (_map.count(name) == 0) {
        throw ModuleException(name, fmt::format("module name '{}' does not exist", name));
    }

    auto policy = _map[name].get();
    std::map<std::string, InputStream *> input_stream;
    for (const auto &input : policy->input_stream()) {
        input_stream[input->name()] = input;
    }

    std::vector<std::string> module_names;
    for (const auto &mod : policy->modules()) {
        module_names.push_back(mod->name());
    }
    policy->stop();

    for (const auto &mod_name : module_names) {
        _registry->handler_manager()->module_remove(mod_name);
    }

    for (const auto &input : input_stream) {
        _remove_input_if_unused(input.first, input.second, name);
    }

    _map.erase(name);
}

void PolicyManager::_remove_input_if_unused(const std::string &input_name, InputStream *input, const std::string &leaving_policy)
{
    if (input->policies_count() == 1) {
        // if there is only one policy left on the input stream, and that policy is the input resources policy, then remove it
        auto input_resources_name = input_name + "-resources";
        if (leaving_policy != input_resources_name && _map.count(input_resources_name) != 0) {
            auto resources_policy = _map[input_resources_name].get();
            resources_policy->stop();
            _registry->handler_manager()->module_remove(input_resources_name);
            _map.erase(input_resources_name);
        }
    }

    if (!input->policies_count()) {
        _registry->input_manager()->module_remove(input_name);
    }
}
void Policy::info_json(json &j) const
{
    for (auto &tap : _taps) {
        tap->info_json(j["taps"][tap->name()]);
    }
    for (auto &input : _input_streams) {
        input->info_json(j["input"][input->name()]);
    }
    for (auto &mod : _modules) {
        mod->info_json(j["modules"][mod->name()]);
    }
}
void Policy::start()
{
    if (_running) {
        return;
    }
    assert(_input_streams.size());
    spdlog::get("visor")->info("policy [{}]: starting", _name);

    // configurations
    _merge_like_handlers = (config_exists("merge_like_handlers") && config_get<bool>("merge_like_handlers"));

    try {
        for (auto &mod : _modules) {
            spdlog::get("visor")->debug("policy [{}]: starting handler instance: {}", _name, mod->name());
            mod->start();
        }
        // start input stream _after_ modules, since input stream will create a new thread and we need to catch any startup errors
        // from handlers in the same thread we are starting the policy from
        for (auto &input : _input_streams) {
            spdlog::get("visor")->debug("policy [{}]: starting input instance: {}", _name, input->name());
            input->start();
        }
    } catch (...) {
        // undo a partial start: in a sequence, a handler cannot be removed while the next one still runs connected to it
        for (auto &mod : _modules) {
            if (mod->running()) {
                mod->stop();
            }
        }
        throw;
    }
    _running = true;
}
void Policy::stop()
{
    if (!_running) {
        return;
    }
    spdlog::get("visor")->info("policy [{}]: stopping", _name);
    for (auto &input : _input_streams) {
        if (input->running()) {
            if (input->policies_count() <= 1) {
                spdlog::get("visor")->debug("policy [{}]: stopping input instance: {}", _name, input->name());
                input->stop();
            } else {
                spdlog::get("visor")->info("policy [{}]: input instance {} not stopped because it is in use by another policy.", _name, input->name());
            }
        }
        input->remove_policy(this);
    }
    for (auto &mod : _modules) {
        if (mod->running()) {
            spdlog::get("visor")->debug("policy [{}]: stopping handler instance: {}", _name, mod->name());
            mod->stop();
        }
    }
    _running = false;
}

void Policy::json_metrics(json &j, uint64_t period, bool merge)
{
    if (_merge_like_handlers) {
        try {
            auto bucket_map = _get_merged_buckets(false, period, merge);
            for (auto &[bucket, hmod] : bucket_map) {
                auto h_name = hmod->schema_key() + "_merged";
                hmod->window_json(j[name()][h_name], bucket.get());
                if (j[name()][h_name] == nullptr) {
                    j[name()].erase(h_name);
                }
            }
        } catch (const PeriodException &e) {
            spdlog::get("visor")->warn("merge_like_handler for policy {} had a PeriodException, skipping: {}", name(), e.what());
            throw e;
        }
    } else {
        for (auto &mod : modules()) {
            auto hmod = dynamic_cast<StreamHandler *>(mod);
            if (hmod) {
                try {
                    spdlog::stopwatch sw;
                    hmod->window_json(j[name()][hmod->name()], period, merge);
                    if (j[name()][hmod->name()] == nullptr) {
                        j[name()].erase(hmod->name());
                    }
                    spdlog::get("visor")->debug("{} window_json elapsed time: {}", hmod->name(), sw);
                } catch (const PeriodException &e) {
                    spdlog::get("visor")->warn("{} handler for policy {} had a PeriodException, skipping: {}", hmod->name(), name(), e.what());
                    throw e;
                }
            }
        }
    }
}

void Policy::prometheus_metrics(PrometheusSerializer &ser)
{
    if (_merge_like_handlers) {
        auto bucket_map = _get_merged_buckets();
        for (auto &[bucket, hmod] : bucket_map) {
            hmod->window_prometheus(ser, bucket.get(), {{"policy", name()}, {"handler", hmod->schema_key() + "_merged"}});
        }
    } else {
        for (auto &mod : modules()) {
            auto hmod = dynamic_cast<StreamHandler *>(mod);
            if (hmod) {
                spdlog::stopwatch sw;
                hmod->window_prometheus(ser, {{"policy", name()}, {"handler", hmod->name()}});
                spdlog::get("visor")->debug("{} window_prometheus elapsed time: {}", hmod->name(), sw);
            }
        }
    }
}

void Policy::prometheus_metrics(std::stringstream &out)
{
    PrometheusSerializer ser;
    prometheus_metrics(ser);
    out << ser.finalize();
}

bool PolicyManager::opentelemetry_metrics(metrics::v1::ResourceMetrics &resource)
{
    for (const auto &p_mname : module_get_keys()) {
        auto scopes_before = resource.scope_metrics_size();
        try {
            auto [policy, lock] = module_get_locked(p_mname);
            auto scope = resource.add_scope_metrics();
            scope->mutable_scope()->set_name("pktvisor/" + p_mname);
            auto attr = scope->mutable_scope()->add_attributes();
            attr->set_key("policy_name");
            attr->mutable_value()->set_string_value(p_mname);
            policy->opentelemetry_metrics(*scope);
        } catch (const std::exception &) {
            // A policy removed during the push is skipped rather than failing
            // it. One that failed while writing keeps what its earlier handlers
            // wrote, since they marked those windows as sent; the handler that
            // failed dropped its own.
        }
        if (resource.scope_metrics_size() > scopes_before && resource.scope_metrics(scopes_before).metrics_size() == 0) {
            resource.mutable_scope_metrics()->RemoveLast();
        }
    }
    return resource.scope_metrics_size() > 0;
}

std::optional<std::vector<timespec>> next_merged_windows(const std::vector<StreamHandler *> &handlers,
    const std::vector<timespec> &last_starts)
{
    if (handlers.empty()) {
        return std::nullopt;
    }
    std::vector<timespec> starts;
    for (size_t i = 0; i < handlers.size(); ++i) {
        std::optional<timespec> after;
        if (last_starts.size() == handlers.size()) {
            after = last_starts[i];
        }
        auto start = handlers[i]->next_closed_window_start(after);
        if (!start) {
            return std::nullopt;
        }
        starts.push_back(*start);
    }
    return starts;
}

void Policy::_merged_opentelemetry(metrics::v1::ScopeMetrics &scope)
{
    std::vector<StreamHandler *> handlers;
    for (auto &mod : modules()) {
        if (auto hmod = dynamic_cast<StreamHandler *>(mod)) {
            handlers.push_back(hmod);
        }
    }
    // If an export fails, what it wrote is dropped and its window is not
    // marked as sent, so the next push sends it whole.
    auto export_merged = [this, &scope](const BucketMap &bucket_map) {
        auto metrics_before = scope.metrics_size();
        try {
            for (auto &[bucket, hmod] : bucket_map) {
                hmod->window_opentelemetry(scope, bucket.get(), {{"policy", name()}, {"handler", hmod->schema_key() + "_merged"}});
            }
        } catch (...) {
            scope.mutable_metrics()->DeleteSubrange(metrics_before, scope.metrics_size() - metrics_before);
            throw;
        }
    };

    if (std::any_of(handlers.begin(), handlers.end(), [](auto h) { return !h->closes_windows(); })) {
        // A window that never closes is pushed as it grows, once per window
        // length.
        auto last_live = _otel_last_merged_live;
        if (!StreamHandler::live_window_due(_otel_last_merged_live)) {
            return;
        }
        try {
            export_merged(_get_merged_buckets());
        } catch (...) {
            _otel_last_merged_live = last_live;
            throw;
        }
        return;
    }

    // Each handler merges the window it holds by that window's start, so one
    // that closes during the merge changes nothing: what is marked as sent is
    // what was merged.
    while (auto starts = next_merged_windows(handlers, _otel_last_merged)) {
        std::map<StreamHandler *, timespec> start_of;
        for (size_t i = 0; i < handlers.size(); ++i) {
            start_of[handlers[i]] = (*starts)[i];
        }
        export_merged(_get_merged_buckets([&start_of](StreamHandler *hmod, AbstractMetricsBucket *bucket) {
            return hmod->merge_closed(bucket, start_of.at(hmod));
        }));
        _otel_last_merged = std::move(*starts);
    }
}

void Policy::opentelemetry_metrics(metrics::v1::ScopeMetrics &scope)
{
    if (_merge_like_handlers) {
        _merged_opentelemetry(scope);
    } else {
        for (auto &mod : modules()) {
            auto hmod = dynamic_cast<StreamHandler *>(mod);
            if (hmod) {
                spdlog::stopwatch sw;
                // A handler marks its windows as sent only once written, so if
                // it fails what it wrote is dropped and sent whole next time.
                auto metrics_before = scope.metrics_size();
                try {
                    hmod->window_opentelemetry(scope, {{"policy", name()}, {"handler", hmod->name()}});
                } catch (...) {
                    scope.mutable_metrics()->DeleteSubrange(metrics_before, scope.metrics_size() - metrics_before);
                    throw;
                }
                spdlog::get("visor")->debug("{} window_opentelemetry elapsed time: {}", hmod->name(), sw);
            }
        }
    }
}

Policy::BucketMap Policy::_get_merged_buckets(bool prometheus, uint64_t period, bool merged)
{
    return _get_merged_buckets([prometheus, period, merged](StreamHandler *hmod, AbstractMetricsBucket *bucket) {
        return hmod->merge(bucket, period, prometheus, merged);
    });
}

Policy::BucketMap Policy::_get_merged_buckets(const std::function<std::unique_ptr<AbstractMetricsBucket>(StreamHandler *, AbstractMetricsBucket *)> &merge)
{
    BucketMap bucket_map;
    for (auto &mod : modules()) {
        auto hmod = dynamic_cast<StreamHandler *>(mod);
        assert(hmod);
        if (bucket_map.empty()) {
            bucket_map.emplace(merge(hmod, nullptr), hmod);
            continue;
        }
        for (auto &[bucket, handler] : bucket_map) {
            bool is_last = (bucket == std::prev(bucket_map.end())->first);
            if (!is_last && (hmod->schema_key() != handler->schema_key())
                && (hmod->version() != handler->version())) {
                continue;
            }
            auto new_bucket = merge(hmod, bucket.get());
            if (!new_bucket) {
                break;
            } else if (is_last) {
                bucket_map.emplace(std::move(new_bucket), hmod);
                break;
            }
        }
    }
    return bucket_map;
}
}
