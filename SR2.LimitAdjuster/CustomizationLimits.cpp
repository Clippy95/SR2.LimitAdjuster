#include "pch.h"
#include "CustomizationLimits.h"
#include "ClothingMaterialCopy.h"
#include "sr_xml.h"
#include <array>
#include <cstddef>
#include <exception>
extern void lprintf(const char*, ...);
namespace CustomizationLimits {
namespace {
constexpr uint32_t kCapacity = 16384;
constexpr uint32_t kStride = 52;
constexpr uint32_t kObscuredVids = 262144;
constexpr uint32_t kObscuredSlots = 8192;
alignas(16) std::array<std::byte, kCapacity * kStride> components{};
std::array<uint8_t, kObscuredVids> obscuredVids{};
std::array<uint32_t, kObscuredSlots> obscuredSlots{};
SafetyHookInline parseComponents;
struct ArrayOperand { uintptr_t address; uint32_t expected, offset; };
struct ConstantOperand { uintptr_t address; uint32_t expected, replacement; };
constexpr ArrayOperand arrays[]{
    {0x610a96, 0x2ce3158, 0},
    {0x611952, 0x2ce3158, 0},
    {0x7aae1e, 0x2ce3158, 0},
    {0x7ac1eb, 0x2ce3158, 0},
    {0x7ac922, 0x2ce3158, 0},
    {0x7bcebe, 0x2ce3158, 0},
    {0x7bedc4, 0x2ce3158, 0},
    {0x7bf04a, 0x2ce3158, 0},
    {0x7bf42a, 0x2ce3158, 0},
    {0x7bff8e, 0x2ce3158, 0},
    {0x7c08c7, 0x2ce3158, 0},
    {0x7c0df5, 0x2ce3158, 0},
    {0x7c1420, 0x2ce3158, 0},
    {0x7c1498, 0x2ce3158, 0},
    {0x7c27d6, 0x2ce3158, 0},
    {0x7c2d93, 0x2ce3158, 0},
    {0x7c437a, 0x2ce3158, 0},
    {0x7c449f, 0x2ce3158, 0},
    {0x7c4722, 0x2ce3158, 0},
    {0x7c59e6, 0x2ce3158, 0},
    {0x7c5b54, 0x2ce3158, 0},
    {0x7c5f15, 0x2ce3158, 0},
    {0x7c718e, 0x2ce3158, 0},
    {0x7c7f6c, 0x2ce3158, 0},
    {0x7c836a, 0x2ce3158, 0},
    {0x7c86e4, 0x2ce3158, 0},
    {0x7ce5f2, 0x2ce3158, 0},
    {0x7d19ab, 0x2ce3158, 0},
    {0x7d2150, 0x2ce3158, 0},
    {0x7d2f3a, 0x2ce3158, 0},
    {0x7d6456, 0x2ce3158, 0},
    {0x7d72d8, 0x2ce3158, 0},
    {0x7d7647, 0x2ce3158, 0},
    {0x7d789c, 0x2ce3158, 0},
    {0x7d7a37, 0x2ce3158, 0},
    {0x7d7d48, 0x2ce3158, 0},
    {0x81e1c8, 0x2ce3158, 0},
    {0x9e3fe7, 0x2ce3158, 0},
    {0x9e70b1, 0x2ce3158, 0},
    {0x9e7c38, 0x2ce3158, 0},
    {0x9ea491, 0x2ce3158, 0},
    {0x9ea4ba, 0x2ce3158, 0},
    {0xdb06cc, 0x2ce3164, 12},
};
constexpr ArrayOperand vidArrays[]{
    {0x9E4049, 0x21DA450, 0},
    {0x9E4570, 0x21DA450, 0},
};
constexpr ArrayOperand slotArrays[]{
    {0x9E401A, 0x21EB5C0, 0},
    {0x9E43F2, 0x21EB5C0, 0},
};
constexpr ConstantOperand constants[]{
    {0x9E400A, 2000, kObscuredSlots},
    {0x9E43D7, 2000, kObscuredSlots},
    {0x9E403A, 70000, kObscuredVids},
    {0x9E4556, 70000, kObscuredVids},
    {0x610aac, 5000, kCapacity},
    {0x611962, 5000, kCapacity},
    {0x7aae2e, 5000, kCapacity},
    {0x7ac1fc, 5000, kCapacity},
    {0x7ac932, 5000, kCapacity},
    {0x7bcece, 5000, kCapacity},
    {0x7beddb, 5000, kCapacity},
    {0x7bf05c, 5000, kCapacity},
    {0x7bf43c, 5000, kCapacity},
    {0x7bff9e, 5000, kCapacity},
    {0x7c08dc, 5000, kCapacity},
    {0x7c0e0c, 5000, kCapacity},
    {0x7c1434, 5000, kCapacity},
    {0x7c14ac, 5000, kCapacity},
    {0x7c27ec, 5000, kCapacity},
    {0x7c2da3, 5000, kCapacity},
    {0x7c438b, 5000, kCapacity},
    {0x7c44af, 5000, kCapacity},
    {0x7c4732, 5000, kCapacity},
    {0x7c59fc, 5000, kCapacity},
    {0x7c5b68, 5000, kCapacity},
    {0x7c5f2c, 5000, kCapacity},
    {0x7c719f, 5000, kCapacity},
    {0x7c7f7c, 5000, kCapacity},
    {0x7c837c, 5000, kCapacity},
    {0x7c86fc, 5000, kCapacity},
    {0x7ce602, 5000, kCapacity},
    {0x7d19bc, 5000, kCapacity},
    {0x7d215f, 5000, kCapacity},
    {0x7d2f4c, 5000, kCapacity},
    {0x7d646c, 5000, kCapacity},
    {0x7d72ec, 5000, kCapacity},
    {0x7d765c, 5000, kCapacity},
    {0x7d78ac, 5000, kCapacity},
    {0x7d7a4c, 5000, kCapacity},
    {0x7d7d5c, 5000, kCapacity},
    {0x81e1dc, 5000, kCapacity},
    {0x9e70ab, 260000, kCapacity * kStride},
    {0x9e7c2a, 5000, kCapacity},
    {0x9ea4cc, 5000, kCapacity},
    {0xdb06c7, 4999, kCapacity - 1},
    {0x9e3fda, 5000, kCapacity},
    {0x9ea4a3, 5000, kCapacity},
};
[[noreturn]] void Fail(const char* message) {
    lprintf("Customization components: %s", message);
    FatalAppExitA(0, message);
    std::terminate();
}
void* __cdecl ParseComponents(xml_element* item, char slot) {
    const auto variants = xtbl_find(item, "Variants");
    const auto count = xml_count(variants, "Variant");
    const auto wears = xml_count(xtbl_find(item, "Wear_Options"), "Wear_Option");
    const auto used = *reinterpret_cast<const uint32_t*>(0x21EDBE8_g);
    const uint64_t needed = static_cast<uint64_t>(count) * wears;
    if (count > 32 || static_cast<uint64_t>(used) + needed >= kCapacity) {
        const auto name = xtbl_get_req_string_ref(item, "Name");
        lprintf("Clothing item '%s': %u used, %llu additional components, %u variants",
            name ? name : "<unnamed>", used, needed, count);
        Fail("Clothing component table or per-item variant capacity exceeded; see sr2_limitadjuster.txt.");
    }
    for (auto node = xtbl_find(variants, "Variant"); node; node = xtbl_find_next(variants, node, "Variant")) {
        if (xml_count(xtbl_find(xtbl_find(node, "Mesh_Variant_Info"), "Material_List"), "Material_Element") > 32)
            Fail("Clothing variant has more than 32 material names; native parser cannot represent it.");
    }
    const auto wearOptions = xtbl_find(item, "Wear_Options");
    uint64_t vidsNeeded = 0, slotsNeeded = 0;
    for (auto wear = xtbl_find(wearOptions, "Wear_Option"); wear;
         wear = xtbl_find_next(wearOptions, wear, "Wear_Option")) {
        const auto mesh = xtbl_find(wear, "Mesh_Information");
        const auto vids = xml_count(xtbl_find(mesh, "Obscured_VIDs"), "Obscured_VID");
        const auto slots = xml_count(xtbl_find(mesh, "Obscured_slots"), "Obscured_slot");
        if (vids > INT16_MAX || slots > INT16_MAX)
            Fail("Clothing visibility-list count exceeds the native signed 16-bit field.");
        // The native parser copies each wear's lists once for every variant.
        vidsNeeded += static_cast<uint64_t>(vids) * count;
        slotsNeeded += static_cast<uint64_t>(slots) * count;
    }
    const auto vidsUsed = *reinterpret_cast<const uint32_t*>(0x21CAA8C_g);
    const auto slotsUsed = *reinterpret_cast<const uint32_t*>(0x21ED500_g);
    if (vidsUsed + vidsNeeded > kObscuredVids || slotsUsed + slotsNeeded > kObscuredSlots) {
        const auto name = xtbl_get_req_string_ref(item, "Name");
        lprintf("Clothing item '%s': hidden VIDs %u + %llu / %u, slots %u + %llu / %u",
            name ? name : "<unnamed>", vidsUsed, vidsNeeded, kObscuredVids,
            slotsUsed, slotsNeeded, kObscuredSlots);
        Fail("Clothing visibility storage capacity exceeded; see sr2_limitadjuster.txt.");
    }
    return parseComponents.ccall<void*>(item, slot);
}
}
void Install() {
    if (memcmp(reinterpret_cast<const void*>(MaterialCopy::address),
               MaterialCopy::original.data(), MaterialCopy::original.size()) != 0)
        Fail("Clothing material-copy code does not match the supported SR2 executable.");
    for (const auto& row : arrays)
        if (*reinterpret_cast<const uint32_t*>(row.address) != row.expected)
            Fail("Clothing component addresses do not match the supported SR2 executable.");
    for (const auto& row : vidArrays)
        if (*reinterpret_cast<const uint32_t*>(row.address) != row.expected)
            Fail("Clothing VID addresses do not match the supported SR2 executable.");
    for (const auto& row : slotArrays)
        if (*reinterpret_cast<const uint32_t*>(row.address) != row.expected)
            Fail("Clothing slot addresses do not match the supported SR2 executable.");
    for (const auto& row : constants)
        if (*reinterpret_cast<const uint32_t*>(row.address) != row.expected)
            Fail("Clothing component limits do not match the supported SR2 executable.");
    // Preserve initialization if the executable's global constructors ran first.
    memcpy(components.data(), reinterpret_cast<const void*>(0x2CE3158_g), 5000 * kStride);
    for (const auto& row : arrays)
        Memory::VP::Patch<uintptr_t>(row.address, reinterpret_cast<uintptr_t>(components.data()) + row.offset);
    memcpy(obscuredVids.data(), reinterpret_cast<const void*>(0x21DA450_g), 70000);
    memcpy(obscuredSlots.data(), reinterpret_cast<const void*>(0x21EB5C0_g), 2000 * sizeof(uint32_t));
    for (const auto& row : vidArrays)
        Memory::VP::Patch<uintptr_t>(row.address, reinterpret_cast<uintptr_t>(obscuredVids.data()) + row.offset);
    for (const auto& row : slotArrays)
        Memory::VP::Patch<uintptr_t>(row.address, reinterpret_cast<uintptr_t>(obscuredSlots.data()) + row.offset);
    for (const auto& row : constants)
        Memory::VP::Patch<uint32_t>(row.address, row.replacement);
    Memory::VP::Patch(MaterialCopy::address, MaterialCopy::replacement);
    FlushInstructionCache(GetCurrentProcess(), reinterpret_cast<const void*>(MaterialCopy::address),
                          MaterialCopy::replacement.size());
    lprintf("Clothing material lists: fixed native checksum copy for every material (up to 32).");
    parseComponents = safetyhook::create_inline(reinterpret_cast<void*>(0x9E7560_g), reinterpret_cast<void*>(&ParseComponents));
    if (!parseComponents) Fail("Could not install the clothing component bounds check.");
    lprintf("Customization components: 16384 mesh/variant slots (16383 usable), 262144 hidden VIDs, 8192 hidden slots; relocated storage and all lookup bounds");
}
void LogUsage() {
    lprintf("Clothing tables loaded: %u components, %u hidden VIDs, %u hidden slots",
        *reinterpret_cast<const uint32_t*>(0x21EDBE8_g),
        *reinterpret_cast<const uint32_t*>(0x21CAA8C_g),
        *reinterpret_cast<const uint32_t*>(0x21ED500_g));
}

}
