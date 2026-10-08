#include "pch.h"
#include "HavokMemoryLimits.h"
#include <mutex>

extern void lprintf(const char*, ...);
namespace HavokMemoryLimits {
namespace {
using SysAlloc = void*(__cdecl*)(int);
using SysFree = void(__cdecl*)(void*);
const uintptr_t kMallocImm = 0x6F6400_g + 6, kFreeImm = 0x6F640A_g + 6;
const uintptr_t kVanillaAlloc = 0x71A2E0_g, kVanillaFree = 0x71A330_g;
const uintptr_t kBufferBegin = 0x176CC40_g, kBufferEnd = 0x1F6CC40_g;

struct Header { void* raw; uint32_t size; uint32_t magic; };
constexpr uint32_t kMagic = 0x4B564853;   // 'SHVK'
HANDLE g_heap = nullptr;
size_t g_cap = 0, g_used = 0, g_peak = 0;
std::mutex g_lock;
bool g_logged_first = false;

void* Overflow(int size, int align) {
    if (size <= 0) return nullptr;
    if (align < 8) align = 8;
    const size_t total = static_cast<size_t>(size) + static_cast<size_t>(align) + sizeof(Header);
    std::lock_guard<std::mutex> guard(g_lock);
    if (g_used + total > g_cap) {
        lprintf("[Havok memory] overflow heap full: %u of %u bytes used, request %d\n",
                static_cast<unsigned>(g_used), static_cast<unsigned>(g_cap), size);
        return nullptr;
    }
    void* raw = HeapAlloc(g_heap, 0, total);
    if (!raw) return nullptr;
    uintptr_t p = (reinterpret_cast<uintptr_t>(raw) + sizeof(Header) + (align - 1)) & ~static_cast<uintptr_t>(align - 1);
    auto* h = reinterpret_cast<Header*>(p) - 1;
    h->raw = raw; h->size = static_cast<uint32_t>(total); h->magic = kMagic;
    g_used += total;
    if (!g_logged_first) { g_logged_first = true; lprintf("[Havok memory] vanilla 8 MB full; using the overflow heap\n"); }
    if (g_used / (1024 * 1024) > g_peak / (1024 * 1024))   // log each new megabyte reached
        lprintf("[Havok memory] overflow in use: %u KB (cap %u KB)\n", static_cast<unsigned>(g_used / 1024), static_cast<unsigned>(g_cap / 1024));
    if (g_used > g_peak) g_peak = g_used;
    return reinterpret_cast<void*>(p);
}

void* __cdecl HavokAlloc(int size, int align) {
    if (void* p = reinterpret_cast<SysAlloc>(kVanillaAlloc)(size)) return p;
    return Overflow(size, align);
}

void __cdecl HavokFree(void* p) {
    if (!p) return;
    const uintptr_t a = reinterpret_cast<uintptr_t>(p);
    if (a >= kBufferBegin && a < kBufferEnd) { reinterpret_cast<SysFree>(kVanillaFree)(p); return; }
    auto* h = reinterpret_cast<Header*>(p) - 1;
    if (h->magic != kMagic) { lprintf("[Havok memory] free of unknown pointer %p ignored\n", p); return; }
    std::lock_guard<std::mutex> guard(g_lock);
    h->magic = 0;
    g_used -= h->size;
    HeapFree(g_heap, 0, h->raw);
}
}  // namespace

void Install(CIniReader& ini) {
    const int mb = ini.ReadInteger("HAVOK", "ExtraMemoryMB", 32);
    if (mb <= 0) { lprintf("[Havok memory] overflow disabled (ExtraMemoryMB=0): vanilla 8 MB only\n"); return; }
    g_cap = static_cast<size_t>((std::min)(mb, 512)) * 1024 * 1024;
    g_heap = HeapCreate(0, 1024 * 1024, 0);
    if (!g_heap) { lprintf("[Havok memory] HeapCreate failed; vanilla 8 MB only\n"); return; }
    Memory::VP::Patch<uintptr_t>(kMallocImm, reinterpret_cast<uintptr_t>(&HavokAlloc));
    Memory::VP::Patch<uintptr_t>(kFreeImm, reinterpret_cast<uintptr_t>(&HavokFree));
    lprintf("[Havok memory] vanilla 8 MB + overflow up to %d MB\n", (std::min)(mb, 512));
}
}  // namespace HavokMemoryLimits
