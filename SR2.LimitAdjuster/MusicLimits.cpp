#include "pch.h"
#include "MusicLimits.h"
#include <array>
#include <exception>
extern void lprintf(const char*, ...);
namespace MusicLimits {
namespace {
constexpr uint32_t kCapacity=4096;
alignas(16) std::array<uintptr_t,kCapacity> music{};
SafetyHookInline parser;
const std::array<uintptr_t,18> operands{{
    0x466250_g,
    0x479D06_g,
    0x479DBA_g,
    0x47A1FB_g,
    0x47A2C7_g,
    0x47A2FA_g,
    0x47A338_g,
    0x47A360_g,
    0x47A3A6_g,
    0x47A40A_g,
    0x47A4E3_g,
    0x48D746_g,
    0x48D796_g,
    0x48D83A_g,
    0x48D886_g,
    0x48EC26_g,
    0x4901A6_g,
    0x490B87_g,
}};
[[noreturn]] void Fail(const char* message) {
    lprintf("Music registry: %s",message);
    FatalAppExitA(0,message);std::terminate();
}
bool __cdecl ParseMusic(void* node,int index) {
    if(static_cast<unsigned>(index)>=kCapacity)
        Fail("music.xtbl exceeds the 4096-entry music registry. No out-of-bounds entry was written.");
    return parser.ccall<bool>(node,index);
}
}
void Install() {
    for(const auto address:operands)
        if(*reinterpret_cast<const uintptr_t*>(address)!=0xEE7178_g)
            Fail("Unexpected music registry operand; unsupported executable or conflicting patch.");
    if(*reinterpret_cast<const uint32_t*>(0x47A1F4_g)!=8192)
        Fail("Unexpected music registry initialization size.");
    const unsigned char prologue[]{0x81,0xEC,0xAC,0,0,0};
    if(memcmp(reinterpret_cast<void*>(0x479D40_g),prologue,sizeof(prologue)))
        Fail("Unexpected music parser prologue.");
    parser=safetyhook::create_inline(reinterpret_cast<void*>(0x479D40_g),reinterpret_cast<void*>(&ParseMusic));
    if(!parser) Fail("Could not install the music registry bounds check.");
    for(const auto address:operands)
        Memory::VP::Patch<uintptr_t>(address,reinterpret_cast<uintptr_t>(music.data()));
    Memory::VP::Patch<uint32_t>(0x47A1F4_g,static_cast<uint32_t>(sizeof(music)));
    lprintf("Music registry: 2048 -> %u entries; all native accesses relocated; parser bounds checked",kCapacity);
}
}
