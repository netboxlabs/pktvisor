#pragma once

#include <Corrade/Containers/StringView.h>
#include <fmt/format.h>
#include <string>

inline std::string corrade_to_std_string(Corrade::Containers::StringView view)
{
    return {view.data(), view.size()};
}

template <>
struct fmt::formatter<Corrade::Containers::StringView> : fmt::formatter<fmt::string_view> {
    auto format(Corrade::Containers::StringView value, format_context &ctx) const -> format_context::iterator
    {
        return fmt::formatter<fmt::string_view>::format(fmt::string_view{value.data(), value.size()}, ctx);
    }
};
