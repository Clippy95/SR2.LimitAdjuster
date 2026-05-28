#pragma once

#include "framework.h"
#include "include\\IniReader.h"

namespace CLimitAdjuster
{
    constexpr uint32_t kVanillaCustomizationItemsLimit = 1050;
    constexpr uint32_t kVanillaItems3DLimit = 219;
    constexpr uint32_t kVanillaCustomizationLogosLimit = 384;
    constexpr uint32_t kMaxCustomizationLogoIndex = 0xFFFE;
    constexpr uint32_t kAutoCustomizationLogoHeadroom = 20;

    struct CountSetting
    {
        bool auto_mode = true;
        uint32_t value = 0;
    };

    CountSetting read_count_setting(
        CIniReader& ini,
        std::string_view section,
        std::string_view key,
        uint32_t vanilla_limit);

    uint32_t resolve_capacity(
        std::string_view label,
        const CountSetting& setting,
        uint32_t detected_count,
        uint32_t vanilla_limit,
        uint32_t auto_headroom = 0,
        uint32_t hard_max = 0);

    bool should_apply_capacity_patch(
        bool force_dyn,
        const CountSetting& setting,
        uint32_t capacity,
        uint32_t vanilla_limit);
}
