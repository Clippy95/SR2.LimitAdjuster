#include "pch.h"
#include "LimitConfig.h"

extern void lprintf(const char* format, ...);

namespace CLimitAdjuster
{
    static std::string trim_copy(std::string value)
    {
        auto is_space = [](unsigned char ch) { return std::isspace(ch) != 0; };

        value.erase(value.begin(), std::find_if(value.begin(), value.end(), [&](unsigned char ch) {
            return !is_space(ch);
            }));
        value.erase(std::find_if(value.rbegin(), value.rend(), [&](unsigned char ch) {
            return !is_space(ch);
            }).base(), value.end());

        return value;
    }

    CountSetting read_count_setting(
        CIniReader& ini,
        std::string_view section,
        std::string_view key,
        uint32_t vanilla_limit)
    {
        auto raw = trim_copy(ini.ReadString(section, key, "auto"));
        std::string lowered = raw;
        std::transform(lowered.begin(), lowered.end(), lowered.begin(), [](unsigned char ch) {
            return static_cast<char>(std::tolower(ch));
            });

        if (lowered.empty() || lowered == "auto")
            return {};

        if (lowered == "0" || lowered == "-1")
        {
            CountSetting setting{};
            setting.disabled = true;
            setting.auto_mode = false;
            setting.value = 0;
            lprintf("%.*s.%.*s disabled by config value '%s'\n",
                static_cast<int>(section.size()), section.data(),
                static_cast<int>(key.size()), key.data(),
                raw.c_str());
            return setting;
        }

        try
        {
            size_t parsed_chars = 0;
            const auto parsed = std::stoull(lowered, &parsed_chars, 0);
            if (parsed_chars != lowered.size())
                throw std::invalid_argument("trailing characters");

            CountSetting setting{};
            setting.auto_mode = false;
            setting.value = static_cast<uint32_t>((std::min<unsigned long long>)(parsed, (std::numeric_limits<uint32_t>::max)()));

            if (setting.value < vanilla_limit)
            {
                lprintf("%.*s.%.*s requested %u, clamping to vanilla minimum %u\n",
                    static_cast<int>(section.size()), section.data(),
                    static_cast<int>(key.size()), key.data(),
                    setting.value, vanilla_limit);
                setting.value = vanilla_limit;
            }

            return setting;
        }
        catch (...)
        {
            lprintf("%.*s.%.*s value '%s' is invalid, using auto\n",
                static_cast<int>(section.size()), section.data(),
                static_cast<int>(key.size()), key.data(),
                raw.c_str());
            return {};
        }
    }

    uint32_t resolve_capacity(
        std::string_view label,
        const CountSetting& setting,
        uint32_t detected_count,
        uint32_t vanilla_limit,
        uint32_t auto_headroom,
        uint32_t hard_max)
    {
        uint64_t wanted = 0;

        if (setting.auto_mode)
        {
            wanted = (std::max<uint64_t>)(vanilla_limit, static_cast<uint64_t>(detected_count) + auto_headroom);
        }
        else if (setting.disabled)
        {
            wanted = vanilla_limit;
        }
        else
        {
            wanted = (std::max<uint64_t>)(vanilla_limit, setting.value);
            if (wanted < detected_count)
            {
                lprintf("%.*s requested fixed cap %u, but xtbl needs %u. Promoting to %u\n",
                    static_cast<int>(label.size()), label.data(),
                    static_cast<uint32_t>(wanted), detected_count, detected_count);
                wanted = detected_count;
            }
        }

        if (hard_max != 0 && wanted > hard_max)
        {
            lprintf("%.*s requested %llu, clamping to hard max %u\n",
                static_cast<int>(label.size()), label.data(),
                wanted, hard_max);
            wanted = hard_max;
        }

        return static_cast<uint32_t>(wanted);
    }

    bool should_apply_capacity_patch(
        bool force_dyn,
        const CountSetting& setting,
        uint32_t capacity,
        uint32_t vanilla_limit)
    {
        if (setting.disabled)
            return false;

        return force_dyn || !setting.auto_mode || capacity > vanilla_limit;
    }
}
