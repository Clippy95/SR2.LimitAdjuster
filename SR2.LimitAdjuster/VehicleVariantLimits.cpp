#include "pch.h"
#include "VehicleVariantLimits.h"
#include <array>
#include <cstring>
extern void lprintf(const char*, ...);
namespace VehicleVariantLimits {
namespace {
constexpr uint32_t kNativeLimit = 0x10000;
constexpr uint32_t kCapacity = 0x100000;
alignas(16) std::array<unsigned char, kCapacity> buffer{};
SafetyHookMid bufferHook;
void UseStaticBuffer(safetyhook::Context32& ctx) { ctx.ebx = reinterpret_cast<uintptr_t>(buffer.data()); }
}
void Install() {
    // mov eax,10000h / call _alloca ... mov ebx,esp; mov [ebp-60h],ebx ... cmp eax,10000h; ja skip
    const unsigned char store[]{0x8B, 0xDC, 0x89, 0x5D, 0xA0};
    const unsigned char check[]{0x3D, 0x00, 0x00, 0x01, 0x00, 0x0F, 0x87};
    if (*reinterpret_cast<const uint32_t*>(0xAC5877_g) != kNativeLimit
        || std::memcmp(reinterpret_cast<void*>(0xAC5888_g), store, sizeof(store))
        || std::memcmp(reinterpret_cast<void*>(0xAC58DB_g), check, sizeof(check))) {
        lprintf("Vehicle tables: unexpected code at init_vehicle_variant_lookup; native 64 KiB limit retained");
        return;
    }
    bufferHook = safetyhook::create_mid(reinterpret_cast<void*>(0xAC588A_g), UseStaticBuffer);
    if (!bufferHook) {
        lprintf("Vehicle tables: hook failed; native 64 KiB limit retained");
        return;
    }
    Memory::VP::Patch<uint32_t>(0xAC58DC_g, kCapacity);
    lprintf("Vehicle tables: compiled .cvtf limit %u KiB -> %u KiB (static buffer); variants of large tables now register",
        kNativeLimit / 1024, kCapacity / 1024);
}
}
