#pragma once
#include <cstdint>
namespace SR2LimitAdjusterApi {
constexpr uint32_t kExtendedSaveVersion = 1;
struct ExtendedSaveApi {
    uint32_t version;
    uint32_t size;
    uint32_t (__cdecl* has_chunk)(const char* name);
    uint32_t (__cdecl* set_chunk)(const char* name, const void* data, uint32_t size, uint32_t version);
    uint32_t (__cdecl* remove_chunk)(const char* name);
    uint32_t (__cdecl* copy_chunk)(const char* name, void* data, uint32_t capacity,
        uint32_t* size, uint32_t* version);
};
using GetExtendedSaveApi = const ExtendedSaveApi* (__cdecl*)(uint32_t version);
}
