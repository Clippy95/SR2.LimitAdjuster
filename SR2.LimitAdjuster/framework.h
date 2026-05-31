#pragma once

#define WIN32_LEAN_AND_MEAN             // Exclude rarely-used stuff from Windows headers
// Windows Header Files
#include <windows.h>
#include "MemoryMgr.h"
#include <libloaderapi.h>
#include <bit>
#include <cstdint>
#include <safetyhook.hpp>
#include <fstream>
#include <vector>
#include <string>
#include <memory>
#include <algorithm>
#include <filesystem>
#include <mutex>
#include <cstdarg>
#include <unordered_set>
using namespace Memory::VP::DynBase;
static auto HandleDynAddress = GetModuleHandle(nullptr);
template<typename AT>
__declspec(noinline) AT DynAddress(AT address)
{
    static_assert(sizeof(AT) == sizeof(uintptr_t), "AT must be pointer sized");

    uintptr_t inputAddr = std::bit_cast<uintptr_t>(address);

    // This is SR2 exe range, this function should only be really used for the mass conversion of older functions, and from now on we have to rely on MemoryMgr.h from ModUtils -- Clippy95
    if (inputAddr >= 0x00400000ULL && inputAddr <= 0x03559000ULL) {
        uintptr_t baseAddr = std::bit_cast<uintptr_t>(HandleDynAddress);

#ifdef _WIN64
        uintptr_t result = baseAddr - 0x140000000ULL + inputAddr;
#else
        uintptr_t result = baseAddr - 0x400000UL + inputAddr;
#endif
        return std::bit_cast<AT>(result);
    }

    // Return the original address if it's outside the range
    return address;
}

inline uintptr_t operator""_g(unsigned long long val)
{
    return DynAddress(static_cast<uintptr_t>(val));
}

// cdecl
template<typename Ret, typename... Args>
inline Ret cdecl_call(uintptr_t addr, Args... args) {
    return reinterpret_cast<Ret(__cdecl*)(Args...)>(addr)(args...);
}

// stdcall
template<typename Ret, typename... Args>
inline Ret stdcall_call(uintptr_t addr, Args... args) {
    return reinterpret_cast<Ret(__stdcall*)(Args...)>(addr)(args...);
}

// fastcall
template<typename Ret, typename... Args>
inline Ret fastcall_call(uintptr_t addr, Args... args) {
    return reinterpret_cast<Ret(__fastcall*)(Args...)>(addr)(args...);
}

// thiscall
template<typename Ret, typename... Args>
inline Ret thiscall_call(uintptr_t addr, Args... args) {
    return reinterpret_cast<Ret(__thiscall*)(Args...)>(addr)(args...);
}