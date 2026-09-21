#pragma once
#include <cstdint>
namespace SR2LimitAdjusterApi {
    constexpr uint32_t kVersion = 1;
    struct MempoolApi {
        uint32_t version;
        uint32_t size;
        uint32_t (__cdecl* ensure_empty_capacity)(void* pool, uint32_t minimum_bytes,
            uint32_t reserve_bytes, uint32_t growth_granularity);
    };
    using GetMempoolApi = const MempoolApi* (__cdecl*)(uint32_t version);
}
