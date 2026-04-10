/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "GeoDB.h"
#include <cstring>
#include <fmt/format.h>
#include <stdexcept>

namespace visor::geo {

std::ostream &operator<<(std::ostream &os, const City &c)
{
    return os << c.location;
}

MaxmindDB &GeoIP()
{
    static MaxmindDB ip_db(MaxmindDB::Type::Geo);
    return ip_db;
}

MaxmindDB &GeoASN()
{
    static MaxmindDB asn_db(MaxmindDB::Type::Asn);
    return asn_db;
}

void MaxmindDB::enable(const std::string &database_filename, int cache_size)
{
    auto status = MMDB_open(database_filename.c_str(), MMDB_MODE_MMAP, &_mmdb);
    if (status != MMDB_SUCCESS) {
        std::string msg = database_filename + ": " + MMDB_strerror(status);
        throw std::runtime_error(msg);
    }
    if (cache_size != 0) {
        if (_type == Type::Geo) {
            _lru_geo_cache = std::make_unique<LRUList<std::string, City>>(cache_size);
        } else if (_type == Type::Asn) {
            _lru_asn_cache = std::make_unique<LRUList<std::string, std::string>>(cache_size);
        }
    }
    _enabled = true;
}

MaxmindDB::~MaxmindDB()
{
    if (_enabled) {
        MMDB_close(&_mmdb);
    }
}

City MaxmindDB::getGeoLoc(const struct sockaddr *sa) const
{

    if (!_enabled || sa == nullptr) {
        return {};
    }

    int mmdb_error;

    MMDB_lookup_result_s lookup = MMDB_lookup_sockaddr(&_mmdb, sa, &mmdb_error);
    if (mmdb_error != MMDB_SUCCESS || !lookup.found_entry) {
        return City{"Unknown", std::string(), std::string()};
    }

    return _getGeoLoc(&lookup);
}

City MaxmindDB::getGeoLoc(const struct sockaddr_in *sa4) const
{

    if (!_enabled || sa4 == nullptr) {
        return {};
    }

    std::string ip_address;
    if (_lru_geo_cache) {
        ip_address = fmt::format_int(sa4->sin_addr.s_addr).str();
        std::shared_lock lock(_cache_mutex);
        if (auto geoloc = _lru_geo_cache->getValue(ip_address); geoloc.has_value()) {
            return geoloc.value();
        }
    }

    int mmdb_error;

    MMDB_lookup_result_s lookup = MMDB_lookup_sockaddr(&_mmdb, reinterpret_cast<const struct sockaddr *>(sa4), &mmdb_error);
    if (mmdb_error != MMDB_SUCCESS || !lookup.found_entry) {
        if (_lru_geo_cache) {
            std::unique_lock lock(_cache_mutex);
            _lru_geo_cache->put(ip_address, City{"Unknown", std::string(), std::string()});
        }
        return City{"Unknown", std::string(), std::string()};
    }

    if (_lru_geo_cache) {
        auto geoloc = _getGeoLoc(&lookup);
        std::unique_lock lock(_cache_mutex);
        _lru_geo_cache->put(ip_address, geoloc);
        return geoloc;
    }

    return _getGeoLoc(&lookup);
}

City MaxmindDB::getGeoLoc(const struct sockaddr_in6 *sa6) const
{

    if (!_enabled || sa6 == nullptr) {
        return {};
    }

    std::string ip_address;
    if (_lru_geo_cache) {
        ip_address = fmt::format("{}", fmt::join(sa6->sin6_addr.s6_addr, ""));
        std::shared_lock lock(_cache_mutex);
        if (auto geoloc = _lru_geo_cache->getValue(ip_address); geoloc.has_value()) {
            return geoloc.value();
        }
    }

    int mmdb_error;

    MMDB_lookup_result_s lookup = MMDB_lookup_sockaddr(&_mmdb, reinterpret_cast<const struct sockaddr *>(sa6), &mmdb_error);
    if (mmdb_error != MMDB_SUCCESS || !lookup.found_entry) {
        if (_lru_geo_cache) {
            std::unique_lock lock(_cache_mutex);
            _lru_geo_cache->put(ip_address, City{"Unknown", std::string(), std::string()});
        }
        return City{"Unknown", std::string(), std::string()};
    }

    if (_lru_geo_cache) {
        auto geoloc = _getGeoLoc(&lookup);
        std::unique_lock lock(_cache_mutex);
        _lru_geo_cache->put(ip_address, geoloc);
        return geoloc;
    }

    return _getGeoLoc(&lookup);
}

City MaxmindDB::getGeoLoc(const char *ip_address) const
{

    if (!_enabled || ip_address == nullptr) {
        return {};
    }

    if (_lru_geo_cache) {
        std::shared_lock lock(_cache_mutex);
        if (auto geoloc = _lru_geo_cache->getValue(ip_address); geoloc.has_value()) {
            return geoloc.value();
        }
    }

    int gai_error, mmdb_error;

    MMDB_lookup_result_s lookup = MMDB_lookup_string(&_mmdb, ip_address, &gai_error, &mmdb_error);
    if (0 != gai_error || MMDB_SUCCESS != mmdb_error || !lookup.found_entry) {
        if (_lru_geo_cache) {
            std::unique_lock lock(_cache_mutex);
            _lru_geo_cache->put(ip_address, City{"Unknown", std::string(), std::string()});
        }
        return City{"Unknown", std::string(), std::string()};
    }

    if (_lru_geo_cache) {
        auto geoloc = _getGeoLoc(&lookup);
        std::unique_lock lock(_cache_mutex);
        _lru_geo_cache->put(ip_address, geoloc);
        return geoloc;
    }

    return _getGeoLoc(&lookup);
}

City MaxmindDB::_getGeoLoc(MMDB_lookup_result_s *lookup) const
{

    City obj;

    {
        MMDB_entry_data_s result;
        MMDB_get_value(&lookup->entry, &result, "continent", "code", NULL);

        if (result.has_data && result.type == MMDB_DATA_TYPE_UTF8_STRING) {
            obj.location.append(std::string(result.utf8_string, result.data_size));
        }
    }

    {
        MMDB_entry_data_s result;
        MMDB_get_value(&lookup->entry, &result, "country", "names", "en", NULL);
        if (!result.has_data) {
            MMDB_get_value(&lookup->entry, &result, "country", "iso_code", NULL);
        }

        if (result.has_data && result.type == MMDB_DATA_TYPE_UTF8_STRING) {
            obj.location.push_back('/');
            obj.location.append(std::string(result.utf8_string, result.data_size));
        }
    }

    {
        MMDB_entry_data_s result;
        MMDB_get_value(&lookup->entry, &result, "subdivisions", "0", "iso_code", NULL);

        if (result.has_data && result.type == MMDB_DATA_TYPE_UTF8_STRING) {
            obj.location.push_back('/');
            obj.location.append(std::string(result.utf8_string, result.data_size));
        }
    }

    {
        MMDB_entry_data_s result;
        MMDB_get_value(&lookup->entry, &result, "city", "names", "en", NULL);

        if (result.has_data && result.type == MMDB_DATA_TYPE_UTF8_STRING) {
            obj.location.push_back('/');
            obj.location.append(std::string(result.utf8_string, result.data_size));
        }
    }

    {
        MMDB_entry_data_s result;
        MMDB_get_value(&lookup->entry, &result, "location", "latitude", NULL);

        if (result.has_data && result.type == MMDB_DATA_TYPE_DOUBLE) {
            obj.latitude.append(std::to_string(result.double_value));
        }
    }

    {
        MMDB_entry_data_s result;
        MMDB_get_value(&lookup->entry, &result, "location", "longitude", NULL);
        if (result.has_data && result.type == MMDB_DATA_TYPE_DOUBLE) {
            obj.longitude.append(std::to_string(result.double_value));
        }
    }

    return obj;
}

std::string MaxmindDB::getASNString(const struct sockaddr *sa) const
{

    if (!_enabled) {
        return {};
    }

    int mmdb_error;

    MMDB_lookup_result_s lookup = MMDB_lookup_sockaddr(&_mmdb, sa, &mmdb_error);
    if (mmdb_error != MMDB_SUCCESS || !lookup.found_entry) {
        return "Unknown";
    }

    return _getASNString(&lookup);
}

std::string MaxmindDB::getASNString(const struct sockaddr_in *sa4) const
{

    if (!_enabled || sa4 == nullptr) {
        return {};
    }
    std::string ip_address;
    if (_lru_asn_cache) {
        ip_address = fmt::format_int(sa4->sin_addr.s_addr).str();
        std::shared_lock lock(_cache_mutex);
        if (auto asn = _lru_asn_cache->getValue(ip_address); asn.has_value()) {
            return asn.value();
        }
    }

    int mmdb_error;

    MMDB_lookup_result_s lookup = MMDB_lookup_sockaddr(&_mmdb, reinterpret_cast<const struct sockaddr *>(sa4), &mmdb_error);
    if (mmdb_error != MMDB_SUCCESS || !lookup.found_entry) {
        if (_lru_asn_cache) {
            std::unique_lock lock(_cache_mutex);
            _lru_asn_cache->put(ip_address, "Unknown");
        }
        return "Unknown";
    }

    if (_lru_asn_cache) {
        auto asn = _getASNString(&lookup);
        std::unique_lock lock(_cache_mutex);
        _lru_asn_cache->put(ip_address, asn);
        return asn;
    }

    return _getASNString(&lookup);
}

std::string MaxmindDB::getASNString(const struct sockaddr_in6 *sa6) const
{

    if (!_enabled || sa6 == nullptr) {
        return {};
    }

    std::string ip_address;
    if (_lru_asn_cache) {
        ip_address = fmt::format("{}", fmt::join(sa6->sin6_addr.s6_addr, ""));
        std::shared_lock lock(_cache_mutex);
        if (auto asn = _lru_asn_cache->getValue(ip_address); asn.has_value()) {
            return asn.value();
        }
    }

    int mmdb_error;

    MMDB_lookup_result_s lookup = MMDB_lookup_sockaddr(&_mmdb, reinterpret_cast<const struct sockaddr *>(sa6), &mmdb_error);
    if (mmdb_error != MMDB_SUCCESS || !lookup.found_entry) {
        if (_lru_asn_cache) {
            std::unique_lock lock(_cache_mutex);
            _lru_asn_cache->put(ip_address, "Unknown");
        }
        return "Unknown";
    }

    if (_lru_asn_cache) {
        auto asn = _getASNString(&lookup);
        std::unique_lock lock(_cache_mutex);
        _lru_asn_cache->put(ip_address, asn);
        return asn;
    }

    return _getASNString(&lookup);
}

std::string MaxmindDB::getASNString(const char *ip_address) const
{

    if (!_enabled || ip_address == nullptr) {
        return {};
    }

    if (_lru_asn_cache) {
        std::shared_lock lock(_cache_mutex);
        if (auto asn = _lru_asn_cache->getValue(ip_address); asn.has_value()) {
            return asn.value();
        }
    }

    int gai_error, mmdb_error;

    MMDB_lookup_result_s lookup = MMDB_lookup_string(&_mmdb, ip_address, &gai_error, &mmdb_error);
    if (0 != gai_error || MMDB_SUCCESS != mmdb_error || !lookup.found_entry) {
        if (_lru_asn_cache) {
            std::unique_lock lock(_cache_mutex);
            _lru_asn_cache->put(ip_address, "Unknown");
        }
        return "Unknown";
    }

    if (_lru_asn_cache) {
        auto asn = _getASNString(&lookup);
        std::unique_lock lock(_cache_mutex);
        _lru_asn_cache->put(ip_address, asn);
        return asn;
    }

    return _getASNString(&lookup);
}

std::string MaxmindDB::_getASNString(MMDB_lookup_result_s *lookup) const
{

    std::string geoString;

    {
        MMDB_entry_data_s result;
        MMDB_get_value(&lookup->entry, &result, "autonomous_system_number", NULL);

        if (result.has_data) {
            switch (result.type) {
            case MMDB_DATA_TYPE_UINT16:
                geoString.append(std::to_string(result.uint16));
                break;
            case MMDB_DATA_TYPE_INT32:
                geoString.append(std::to_string(result.int32));
                break;
            case MMDB_DATA_TYPE_UINT32:
                geoString.append(std::to_string(result.uint32));
                break;
            case MMDB_DATA_TYPE_UINT64:
                geoString.append(std::to_string(result.uint64));
                break;
            case MMDB_DATA_TYPE_UTF8_STRING:
                geoString.append(std::string(result.utf8_string, result.data_size));
                break;
            }
        }
    }

    {
        MMDB_entry_data_s result;
        MMDB_get_value(&lookup->entry, &result, "autonomous_system_organization", NULL);

        if (result.has_data && result.type == MMDB_DATA_TYPE_UTF8_STRING) {
            geoString.push_back('/');
            geoString.append(std::string(result.utf8_string, result.data_size));
        }
    }

    // expect implicit move
    return geoString;
}
}
