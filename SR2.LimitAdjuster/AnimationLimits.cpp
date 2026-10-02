#include "pch.h"
#include "AnimationLimits.h"
#include "AnimationGroupCollector.h"
#include <array>
#include <cstddef>
#include <cstdint>
#include <exception>
extern void lprintf(const char*, ...);
namespace AnimationLimits {
namespace {
constexpr size_t kAnimations = 10240;
constexpr size_t kSets = 255;
constexpr size_t kTriggers = 32768;
constexpr size_t kBindings = 32768;
constexpr size_t kIK = 16384;
alignas(16) std::array<std::byte, kAnimations * 84> anims{};
alignas(16) std::array<std::byte, kSets * 20> sets{};
alignas(16) std::array<std::byte, kAnimations * 32> library{};
alignas(16) std::array<std::byte, kTriggers * 8> triggers{};
alignas(16) std::array<int32_t, kBindings> group_sets{}, group_handles{};
alignas(16) std::array<std::byte, kIK * 20> ik{};
SafetyHookInline groupCollectorHook;
struct GroupMemory {
    uint32_t read32(uint32_t p) const { return *reinterpret_cast<const uint32_t*>(p); }
    uint8_t read8(uint32_t p) const { return *reinterpret_cast<const uint8_t*>(p); }
    unsigned groupCount() const { return read32(0x25295B8_g); }
    uint32_t groupAddress(unsigned i) const { return 0x2ACDA40_g+96*i; }
    bool validGroup(uint32_t p) const {
        return p>=groupAddress(0) && (p-groupAddress(0))%96==0 &&
            (p-groupAddress(0))/96<groupCount();
    }
    bool validAnimation(uint32_t p) const {
        const auto first=reinterpret_cast<uintptr_t>(anims.data());
        return p>=first && (p-first)%84==0 && (p-first)/84<read32(0x2527D6C_g);
    }
    uint32_t chain(bool state,unsigned tag) const {
        return read32((state?0x168A600_g:0x1689118_g)+tag*4);
    }
    bool permanent(uint32_t animation) const {
        const auto handle=read32(animation+12);
        if(handle>=read32(0x24E1864_g) || handle>=kAnimations) return false;
        const auto entry=reinterpret_cast<uintptr_t>(library.data())+32*handle;
        return (read32(entry+12)&1)!=0 && read32(entry+28)!=0;
    }
    uint32_t objectBase(uint32_t hash) const {
        for(unsigned probe=0;probe<1000;++probe) {
            const auto index=read32(0x2159C60_g+4*((hash%1000+probe)%1000));
            if(index==UINT32_MAX) return 0;
            if(index>=1000) return 0;
            const auto base=0x215AC00_g+12*index;
            if(read32(base+8)==hash) return base;
        }
        return 0;
    }
};
char __cdecl CollectGroupAnimations(uint32_t* output,int* count,uint32_t group) {
    GroupMemory memory;
    AnimationGroupCollector::Result result;
    const auto okay=AnimationGroupCollector::Copy(memory,group,output,count,&result);
    if(!okay) lprintf("Animation group %08X: invalid graph or %u non-permanent clips exceed the native 100-slot streaming output; list rejected without writing out of bounds",group,static_cast<unsigned>(result.files.size()));
    return okay;
}
struct ArrayOperand { uintptr_t address, expected; size_t offset; };
struct ConstantOperand { uintptr_t address; uint32_t expected, replacement; };
#include "AnimationLimitOperands.h"
[[noreturn]] void Fail(uintptr_t address) {
    lprintf("Animation limits: unexpected operand at %08X; refusing partial installation", address);
    FatalAppExitA(0, "Animation limits: executable operands do not match the supported SR2 build.");
    std::terminate();
}
template<class Range> void Verify(const Range& rows) {
    for(const auto& row : rows)
        if(*reinterpret_cast<const uint32_t*>(row.address) != row.expected) Fail(row.address);
}
template<class Range, class Storage> void Relocate(const Range& rows, Storage& storage) {
    for(const auto& row : rows)
        Memory::VP::Patch<uintptr_t>(row.address, reinterpret_cast<uintptr_t>(storage.data()) + row.offset);
}
}
void Install() {
    const unsigned char collectorEntry[]{0x81,0xEC,0xB8,0x01,0x00,0x00};
    if(memcmp(reinterpret_cast<const void*>(0xA81F80_g),collectorEntry,sizeof(collectorEntry))) Fail(0xA81F80_g);
    Verify(anims_operands); Verify(sets_operands); Verify(library_operands);
    Verify(triggers_operands); Verify(constant_operands);
    Verify(group_sets_operands); Verify(group_handles_operands); Verify(ik_operands);
    Relocate(anims_operands, anims); Relocate(sets_operands, sets);
    Relocate(library_operands, library); Relocate(triggers_operands, triggers);
    Relocate(group_sets_operands, group_sets); Relocate(group_handles_operands, group_handles); Relocate(ik_operands, ik);
    for(const auto& row : constant_operands)
        Memory::VP::Patch<uint32_t>(row.address, row.replacement);
    groupCollectorHook=safetyhook::create_inline(reinterpret_cast<void*>(0xA81F80_g),reinterpret_cast<void*>(&CollectGroupAnimations));
    if(!groupCollectorHook) Fail(0xA81F80_g);
    lprintf("Animation limits: 10240 records/handles, 255 skeleton sets, 32768 bindings/events, 16384 IK events; bounded action-node animation collection");
}
}
