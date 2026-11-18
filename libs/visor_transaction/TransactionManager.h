/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#pragma once

#include "robin_hood.h"
#include <algorithm>
#include <chrono>
#include <cstdint>
#include <limits>
#include <memory>
#include <vector>

namespace visor::lib::transaction {

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

static inline void timespec_diff(struct timespec *a, struct timespec *b,
    struct timespec *result)
{
    if (a->tv_sec > b->tv_sec) {
        result->tv_sec = a->tv_sec - b->tv_sec;
    } else {
        result->tv_sec = b->tv_sec - a->tv_sec;
    }
    result->tv_nsec = a->tv_nsec - b->tv_nsec;
    if (result->tv_nsec < 0) {
        --result->tv_sec;
        result->tv_nsec += 1000000000L;
    }
}

enum class Result {
    NotExist,
    TimedOut,
    Valid
};

struct Transaction {
    timespec startTS;
    timespec totalTS{0, 0};
};

template <typename XactID, typename TransactionType, typename Hash = hash_pair>
class TransactionManager
{
    static_assert(std::is_base_of<Transaction, TransactionType>::value, "TransactionType must inherit from Transaction structure");
    typedef robin_hood::unordered_node_map<XactID, TransactionType, Hash> XactMap;

    uint32_t _ttl_secs{0};
    uint32_t _ttl_ms{0};
    XactMap _transactions;
    // While a transaction is open, none started before this. It can be earlier than the oldest open one, once
    // maybe_end_transaction or purge_old_transactions has ended that, which costs expire_transactions one scan.
    int64_t _oldest_start_ns{std::numeric_limits<int64_t>::max()};

    static int64_t to_ns(timespec t)
    {
        return static_cast<int64_t>(t.tv_sec) * 1000000000 + t.tv_nsec;
    }

public:
    TransactionManager(uint32_t ttl_ms = 5000)
    {
        if (ttl_ms > 1000) {
            _ttl_secs = ttl_ms / 1000;
            _ttl_ms = ttl_ms - _ttl_secs * 1000;
        } else {
            _ttl_ms = ttl_ms;
        }
    }

    void start_transaction(XactID id, TransactionType type)
    {
        _oldest_start_ns = std::min(_oldest_start_ns, to_ns(type.startTS));
        _transactions[id] = type;
    }

    std::pair<Result, TransactionType> maybe_end_transaction(XactID id, timespec endTS)
    {
        if (_transactions.find(id) != _transactions.end()) {
            auto result = _transactions[id];
            timespec_diff(&endTS, &result.startTS, &result.totalTS);
            _transactions.erase(id);
            if (result.totalTS.tv_sec > _ttl_secs) {
                return std::pair<Result, TransactionType>(Result::TimedOut, result);
            } else if (result.totalTS.tv_sec == _ttl_secs && (result.totalTS.tv_nsec / 1.0e6) >= _ttl_ms) {
                return std::pair<Result, TransactionType>(Result::TimedOut, result);
            } else {
                return std::pair<Result, TransactionType>(Result::Valid, result);
            }
        } else {
            return std::pair<Result, TransactionType>(Result::NotExist, TransactionType());
        }
    }

    size_t purge_old_transactions(timespec now)
    {
        std::vector<XactID> timed_out;
        for (auto i : _transactions) {
            if (now.tv_sec >= _ttl_secs + i.second.startTS.tv_sec) {
                timed_out.push_back(i.first);
            }
        }
        for (auto i : timed_out) {
            _transactions.erase(i);
        }
        return timed_out.size();
    }

    // Ends every transaction open for at least the TTL at `now`, the age at which maybe_end_transaction
    // times a reply out, and passes each one to on_expired. Returns how many ended. Scans the open
    // transactions only when the oldest can have expired.
    template <typename OnExpired>
    size_t expire_transactions(timespec now, OnExpired &&on_expired)
    {
        const int64_t ttl_ns = static_cast<int64_t>(_ttl_secs) * 1000000000 + static_cast<int64_t>(_ttl_ms) * 1000000;
        const int64_t now_ns = to_ns(now);
        if (_transactions.empty() || now_ns - _oldest_start_ns < ttl_ns) {
            return 0;
        }
        std::vector<XactID> expired;
        int64_t oldest_open = std::numeric_limits<int64_t>::max();
        for (const auto &i : _transactions) {
            const int64_t start_ns = to_ns(i.second.startTS);
            if (now_ns - start_ns >= ttl_ns) {
                expired.push_back(i.first);
            } else {
                oldest_open = std::min(oldest_open, start_ns);
            }
        }
        _oldest_start_ns = oldest_open;
        for (const auto &id : expired) {
            auto it = _transactions.find(id);
            on_expired(it->second);
            _transactions.erase(it);
        }
        return expired.size();
    }

    void clear()
    {
        _transactions.clear();
        _oldest_start_ns = std::numeric_limits<int64_t>::max();
    }

    typename XactMap::size_type open_transaction_count() const
    {
        return _transactions.size();
    }
};

}
