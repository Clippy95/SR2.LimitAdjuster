#include "pch.h"
#include "RigLimits.h"
#include <usercaller.hpp>
#include <safetyhook_inline.hpp>
#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <mutex>

extern void lprintf(const char*, ...);
namespace RigLimits {
namespace {
constexpr uint32_t kStride=72, kInitial=256, kMaximum=65535;
std::byte* g_rigs=nullptr;
uint32_t g_capacity=0;
std::mutex g_mutex;
using NewRigAbi=uc::abi<uc::eax_ret<void*>,uc::edi_arg<const char*>,uc::stack_arg<void*>,uc::stack_arg<int>>;
uc::inline_hook<NewRigAbi> g_new_rig;
struct Operand { uintptr_t address; uint32_t offset; };
const std::array<Operand,12> kBaseOperands{{
    {0x4A4093_g,0},{0x4A468D_g,0},{0x6E8907_g,0},{0xADB411_g,0},
    {0xCE076A_g,0},{0xCE07A8_g,0},{0xCE0B6C_g,0},{0xCE0BC2_g,0},
    {0xCEC0F3_g,0},{0xCEC788_g,0},{0xCE0B4B_g,32},{0xCEC097_g,32}
}};
const std::array<Operand,4> kEndOperands{{
    {0xCE078C_g,0},{0xCE0BDE_g,0},{0xCE0B5C_g,32},{0xCEC0C3_g,32}
}};
const std::array<uintptr_t,2> kSizeOperands{{0xCE07A1_g,0xCEC781_g}};
[[noreturn]] void Fail(const char* text) {
    lprintf("Rig registry: %s",text);FatalAppExitA(0,text);std::terminate();
}
void Grow(uint32_t required) {
    if(required<=g_capacity) return;
    if(required>kMaximum) Fail("Rig registry exceeds its supported index range.");
    const auto capacity=(std::min)(kMaximum,(std::max)(required,g_capacity?g_capacity*2:kInitial));
    if(!VirtualAlloc(g_rigs,capacity*kStride,MEM_COMMIT,PAGE_READWRITE))
        Fail("Could not commit memory for the expanded animation rig registry.");
    for(const auto& operand:kEndOperands)
        Memory::VP::Patch<uintptr_t>(operand.address,reinterpret_cast<uintptr_t>(g_rigs)+capacity*kStride+operand.offset);
    for(const auto address:kSizeOperands) Memory::VP::Patch<uint32_t>(address,capacity*kStride);
    lprintf("Rig registry: %u -> %u slots (%u committed bytes)",g_capacity,capacity,capacity*kStride);
    g_capacity=capacity;
}
void* __cdecl NewRig(const char* filename,void* data,int size) {
    std::scoped_lock lock(g_mutex);
    auto* result=g_new_rig.unsafe_call_original(filename,data,size);
    if(result || std::strlen(filename)>=32) return result;
    // The native allocator returns null only for a long name or a full array.
    Grow(g_capacity+1);
    result=g_new_rig.unsafe_call_original(filename,data,size);
    if(!result) Fail("Animation rig allocation failed after growing the registry.");
    return result;
}
}
void Install() {
    for(const auto& operand:kBaseOperands)
        if(*reinterpret_cast<const uintptr_t*>(operand.address)!=0x251FB60_g+operand.offset)
            Fail("Rig array operand differs from the supported executable.");
    for(const auto& operand:kEndOperands)
        if(*reinterpret_cast<const uintptr_t*>(operand.address)!=0x251FB60_g+kInitial*kStride+operand.offset)
            Fail("Rig loop bound differs from the supported executable.");
    for(const auto address:kSizeOperands)
        if(*reinterpret_cast<const uint32_t*>(address)!=kInitial*kStride)
            Fail("Rig initialization size differs from the supported executable.");
    for(uint32_t i=0;i<kInitial;++i)
        if(*reinterpret_cast<const uint32_t*>(0x251FB80_g+i*kStride)&1)
            Fail("Rig capacity hooks must be installed before animation preload.");
    g_rigs=static_cast<std::byte*>(VirtualAlloc(nullptr,kMaximum*kStride,MEM_RESERVE,PAGE_READWRITE));
    if(!g_rigs) Fail("Could not reserve address space for animation rigs.");
    const auto first=reinterpret_cast<uintptr_t>(g_rigs);
    if((first^static_cast<uintptr_t>(first+kMaximum*kStride+32))&0x80000000u)
        Fail("Rig reservation crosses a native signed-pointer comparison boundary.");
    Grow(kInitial);
    for(const auto& operand:kBaseOperands)
        Memory::VP::Patch<uintptr_t>(operand.address,first+operand.offset);
    if(!g_new_rig.create(0xCE0B30_g,NewRig)) Fail("Could not install the rig growth hook.");
}
}
