#include "pch.h"
#include "AnimationLimits.h"
#include <array>
#include <cstddef>
#include <cstdint>
#include <exception>
extern void lprintf(const char*, ...);
namespace AnimationLimits {
namespace {
constexpr size_t kAnimations = 8192;
constexpr size_t kSets = 255;
constexpr size_t kTriggers = 16384;
alignas(16) std::array<std::byte, kAnimations * 84> anims{};
alignas(16) std::array<std::byte, kSets * 20> sets{};
alignas(16) std::array<std::byte, kAnimations * 32> library{};
alignas(16) std::array<std::byte, kTriggers * 8> triggers{};
alignas(16) std::array<int32_t, 16384> group_sets{}, group_handles{};
alignas(16) std::array<std::byte, 8192 * 20> ik{};
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
    Verify(anims_operands); Verify(sets_operands); Verify(library_operands);
    Verify(triggers_operands); Verify(constant_operands);
    Verify(group_sets_operands); Verify(group_handles_operands); Verify(ik_operands);
    Relocate(anims_operands, anims); Relocate(sets_operands, sets);
    Relocate(library_operands, library); Relocate(triggers_operands, triggers);
    Relocate(group_sets_operands, group_sets); Relocate(group_handles_operands, group_handles); Relocate(ik_operands, ik);
    for(const auto& row : constant_operands)
        Memory::VP::Patch<uint32_t>(row.address, row.replacement);
    lprintf("Animation limits: 8192 records/handles, 255 skeleton sets, 16384 bindings/events");
}
}
