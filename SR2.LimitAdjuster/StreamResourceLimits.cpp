#include "pch.h"
#include "StreamResourceLimits.h"
#include "sr_xml.h"
#include <safetyhook_inline.hpp>
#include <array>
#include <limits>

extern void lprintf(const char*, ...);
namespace StreamResourceLimits {
namespace {
struct Resource { uint32_t flags; const char** files; void* post_load; };
struct HashPair { const char* filename; uint32_t resource; };
struct FilenameHash { uintptr_t vtable; uint32_t capacity; HashPair* pairs; uint32_t count,max_probe; };
static_assert(sizeof(Resource)==12 && sizeof(HashPair)==8 && sizeof(FilenameHash)==20);
constexpr uint32_t kInitialResources=1000,kInitialFiles=6800;
constexpr uint32_t kMaxResources=0x8000;
Resource* g_resources=nullptr;
uint32_t g_resource_capacity=0;
std::vector<const char*> g_files;
std::vector<HashPair> g_hash_storage;
std::unordered_set<std::string> g_filenames;
SafetyHookInline g_initialize,g_reset;
std::array<SafetyHookMid,4> g_creators;
using RegisterAbi=uc::abi<uc::eax_ret<uintptr_t>,uc::eax_arg<uint32_t>,uc::ecx_arg<const char*>>;
uc::inline_hook<RegisterAbi> g_register;
constexpr uint32_t kCharacterSlots=10;
constexpr uint32_t kCharacterCpuBytes=2*1024*1024;
constexpr uint32_t kCharacterGpuBytes=20*1024*1024;
int __cdecl InitializeContainers(uint32_t* config) {
    config[1]=kCharacterCpuBytes;
    config[3]=kCharacterGpuBytes;
    return reinterpret_cast<int(__cdecl*)(uint32_t*)>(0xA78E60_g)(config);
}
const std::array<uintptr_t,4> kCreateSites{{0x4A4216_g,0xA77599_g,0xADAF17_g,0xADAF7D_g}};
[[noreturn]] void Fail(const char* message) {
    lprintf("Streaming registry: %s",message);FatalAppExitA(0,message);std::terminate();
}
FilenameHash& Hash() { return *reinterpret_cast<FilenameHash*>(0x2F9B2BC_g); }
void GrowResources(uint32_t required) {
    if(required>kMaxResources) Fail("Streaming resource registry exceeds the native signed 16-bit filename index range.");
    if(required<=g_resource_capacity) return;
    const auto capacity=(std::min)(kMaxResources,(std::max)(required,g_resource_capacity?g_resource_capacity*2:kInitialResources));
    if(!VirtualAlloc(g_resources,capacity*sizeof(Resource),MEM_COMMIT,PAGE_READWRITE))
        Fail("Could not commit streaming resource registry storage.");
    lprintf("Streaming resources: %u -> %u slots",g_resource_capacity,capacity);
    g_resource_capacity=capacity;
}
void GrowFiles() {
    const uint32_t count=*reinterpret_cast<uint32_t*>(0x2529E40_g);
    if(count<g_files.size()) return;
    if(count!=g_files.size() || g_files.size()>SIZE_MAX/sizeof(const char*)/2)
        Fail("Invalid streaming filename count or exhausted address space.");
    const auto old_base=reinterpret_cast<uintptr_t>(g_files.data());
    const auto old_end=old_base+g_files.size()*sizeof(const char*);
    g_files.resize(g_files.size()*2,nullptr);
    const auto new_base=reinterpret_cast<uintptr_t>(g_files.data());
    const uint32_t resources=*reinterpret_cast<uint32_t*>(0x2529E38_g);
    if(resources>g_resource_capacity) Fail("Streaming resource count exceeds committed storage.");
    for(uint32_t i=0;i<resources;++i) if(g_resources[i].files) {
        const auto old=reinterpret_cast<uintptr_t>(g_resources[i].files);
        if(old<old_base || old>=old_end) Fail("Streaming resource has an invalid filename run.");
        g_resources[i].files=reinterpret_cast<const char**>(new_base+old-old_base);
    }
    auto& cursor=*reinterpret_cast<uintptr_t*>(0x347B088_g);
    if(cursor>=old_base && cursor<=old_end) cursor=new_base+cursor-old_base;
    *reinterpret_cast<const char***>(0x2529E44_g)=g_files.data();
    lprintf("Streaming filenames: %u -> %u slots",count,static_cast<unsigned>(g_files.size()));
}
void GrowHash() {
    auto& hash=Hash();
    if(hash.count+1<=hash.capacity*3/4) return;
    if(!hash.capacity || hash.capacity>SIZE_MAX/sizeof(HashPair)/2)
        Fail("Invalid streaming filename hash capacity.");
    const auto old_capacity=hash.capacity,old_count=hash.count;
    const HashPair empty{*reinterpret_cast<const char**>(0xEB80F0_g),*reinterpret_cast<uint32_t*>(0xEB80F4_g)};
    std::vector<HashPair> next(old_capacity*2,empty);
    uint32_t count=0,max_probe=1;
    for(uint32_t i=0;i<old_capacity;++i) {
        const auto pair=hash.pairs[i];
        if(pair.filename==empty.filename && pair.resource==empty.resource) continue;
        if(!pair.filename) Fail("Streaming filename hash contains a null name.");
        auto slot=str_to_hash(pair.filename)%next.size();
        uint32_t probe=1;
        while(next[slot].filename!=empty.filename || next[slot].resource!=empty.resource) {
            slot=(slot+1)%next.size();++probe;
        }
        next[slot]=pair;++count;max_probe=(std::max)(max_probe,probe);
    }
    if(count!=old_count) Fail("Streaming filename hash count does not match its entries.");
    g_hash_storage.swap(next);
    hash.pairs=g_hash_storage.data();hash.capacity=static_cast<uint32_t>(g_hash_storage.size());
    hash.count=count;hash.max_probe=max_probe;
    lprintf("Streaming filename hash: %u -> %u slots",old_capacity,hash.capacity);
}
const char* __stdcall StoreFilename(const char* filename) {
    // The old 192 KiB direct-add string pool is independent of slot capacity.
    return g_filenames.emplace(filename).first->c_str();
}
uintptr_t __cdecl RegisterFile(uint32_t resource,const char* filename) {
    if(resource>=g_resource_capacity) Fail("Filename registration references an unallocated streaming resource.");
    GrowFiles();GrowHash();
    return g_register.unsafe_call_original(resource,filename);
}
int __cdecl ResetDatabase() {
    *reinterpret_cast<uint32_t*>(0x2529E38_g)=0;
    *reinterpret_cast<uint32_t*>(0x2529E40_g)=0;
    *reinterpret_cast<uintptr_t*>(0x347B088_g)=0;
    for(uint32_t i=0;i<g_resource_capacity;++i) {
        g_resources[i].flags&=0xFF00000F;g_resources[i].files=nullptr;g_resources[i].post_load=nullptr;
    }
    std::fill(g_files.begin(),g_files.end(),nullptr);
    return 0;
}
int __cdecl InitializeDatabase() {
    GrowResources(kInitialResources);
    if(g_files.empty()) g_files.resize(kInitialFiles,nullptr);
    *reinterpret_cast<Resource**>(0x2529E3C_g)=g_resources;
    *reinterpret_cast<const char***>(0x2529E44_g)=g_files.data();
    *reinterpret_cast<uintptr_t*>(0x2529E48_g)=0x2771278_g;
    reinterpret_cast<void(__cdecl*)()>(0xA77180_g)(); // Native string/hash initialization.
    g_hash_storage.clear();g_filenames.clear();
    return ResetDatabase();
}
}
void Install() {
    for(const auto site:kCreateSites) {
        if(*reinterpret_cast<const uint8_t*>(site)!=0xA3 ||
           *reinterpret_cast<const uintptr_t*>(site+1)!=0x2529E38_g)
            Fail("Streaming resource creation site differs from the supported executable.");
    }
    if(*reinterpret_cast<const uint32_t*>(0xA774F0_g)!=6800*4 ||
       *reinterpret_cast<const uint32_t*>(0xA7750F_g)!=1000*12 ||
       *reinterpret_cast<const uint8_t*>(0xA771F8_g)!=0xE8 ||
       0xA771FD_g+*reinterpret_cast<const int32_t*>(0xA771F9_g)!=0xC06D60_g)
        Fail("Streaming registry allocation sites differ from the supported executable.");
    if(*reinterpret_cast<const uint32_t*>(0x2529E38_g))
        Fail("Streaming registry hooks must be installed before resource registration.");
    g_resources=static_cast<Resource*>(VirtualAlloc(nullptr,kMaxResources*sizeof(Resource),MEM_RESERVE,PAGE_READWRITE));
    if(!g_resources) Fail("Could not reserve streaming resource address space.");
    g_initialize=safetyhook::create_inline(0xA774E0_g,InitializeDatabase);
    g_reset=safetyhook::create_inline(0xA77490_g,ResetDatabase);
    if(!g_initialize || !g_reset || !g_register.create(0xA773E0_g,RegisterFile))
        Fail("Could not install streaming registry capacity hooks.");
    uc::patch_call(0xA771F8_g,StoreFilename);
    for(size_t i=0;i<kCreateSites.size();++i) {
        // EAX is the new count, before the native store and first slot access.
        g_creators[i]=safetyhook::create_mid(kCreateSites[i],[](SafetyHookContext& ctx){GrowResources(ctx.eax);});
        if(!g_creators[i]) Fail("Could not install streaming resource growth guard.");
    }
    // malloc totals and the strides passed to the native container must agree.
    if(*reinterpret_cast<uint8_t*>(0x51F1FA_g)!=0x68 ||
       *reinterpret_cast<uint32_t*>(0x51F1FB_g)!=0x129000*kCharacterSlots ||
       *reinterpret_cast<uint8_t*>(0x51F20C_g)!=0x68 ||
       *reinterpret_cast<uint32_t*>(0x51F20D_g)!=0x400000*kCharacterSlots ||
       *reinterpret_cast<uint32_t*>(0x51F84E_g)!=0x129000 ||
       *reinterpret_cast<uint32_t*>(0x51F7CB_g)!=0x400000 ||
       *reinterpret_cast<uint32_t*>(0x51F7D4_g)!=kCharacterSlots ||
       *reinterpret_cast<uint8_t*>(0x51F9C5_g)!=0xE8 ||
       0x51F9CA_g+*reinterpret_cast<int32_t*>(0x51F9C6_g)!=0xA78E60_g)
        Fail("Character streaming boot layout differs from the supported executable.");
    Memory::VP::Patch<uint32_t>(0x51F1FB_g,kCharacterCpuBytes*kCharacterSlots);
    Memory::VP::Patch<uint32_t>(0x51F20D_g,kCharacterGpuBytes*kCharacterSlots);
    Memory::VP::InjectHook(0x51F9C5_g,InitializeContainers,Memory::VP::HookType::Call);
    lprintf("Character streaming: %u native slots, %u CPU / %u GPU bytes each",kCharacterSlots,kCharacterCpuBytes,kCharacterGpuBytes);
    lprintf("Streaming resources, filename runs, filename hash and strings grow during registration.");
}
}
