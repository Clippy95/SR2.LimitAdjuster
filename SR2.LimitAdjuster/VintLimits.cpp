#include "pch.h"
#include "VintLimits.h"

extern void lprintf(const char*, ...);
namespace VintLimits {
namespace {
struct Factory {
    uintptr_t* vtable;
    uint8_t* avail;
    uint8_t* active;
    uint32_t used;
    uint32_t max;
    uint8_t* array;
};
constexpr uint32_t kNext = 0x14, kPrev = 0x18;
constexpr uint32_t kHardMax = 16384;
constexpr int kPoolCount = 4;

typedef void* (__thiscall* ThiscallFn)(void*);

struct Pool {
    const char* name;
    const char* key;
    uint32_t vanilla;
    uint32_t fallback;
    uint32_t size;
    uintptr_t init;
    uintptr_t factory;
    uintptr_t constructor;
    uintptr_t allocate;
    uint32_t count;
};
Pool g_pools[kPoolCount] = {
    {"bitmap","Bitmaps",0x360,2048,0xC4,0xBA14B0_g,0xEBE3F8_g,0xBA0BF0_g,0xBA15E0_g,0},
    {"group","Groups",0x14B,768,0x98,0xB9CA60_g,0xEBE014_g,0xB9C390_g,0xB9CB90_g,0},
    {"text","Texts",0x158,768,0xF4,0xBA4350_g,0xEBE794_g,0xBA2790_g,0xBA4480_g,0},
    {"bitmap_circle","BitmapCircles",0x40,192,0xCC,0xBA5E30_g,0xEBE970_g,0xBA5460_g,0xBA5F60_g,0},
};
SafetyHookInline g_init_hooks[kPoolCount];
uintptr_t g_allocate[kPoolCount];
bool g_reported[kPoolCount];

uint8_t*& Next(uint8_t* object) { return *(uint8_t**)(object+kNext); }
uint8_t*& Prev(uint8_t* object) { return *(uint8_t**)(object+kPrev); }
uint32_t Read32(const uint8_t* p) { return *(const uint32_t*)p; }

// Replaces the native factory init: same object layout and free list, larger array, own memory.
template<int I> bool __cdecl InitPool() {
    const Pool& pool=g_pools[I];
    Factory* factory=(Factory*)pool.factory;
    if(factory->array) return false;
    const uint32_t bytes=sizeof(uint32_t)+pool.count*pool.size;
    uint8_t* block=(uint8_t*)VirtualAlloc(nullptr,bytes,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE);
    if(!block) {
        lprintf("Vint %s pool: could not allocate %u objects; keeping vanilla %u",pool.name,pool.count,pool.vanilla);
        return g_init_hooks[I].ccall<bool>();
    }
    *(uint32_t*)block=pool.count;
    uint8_t* objects=block+sizeof(uint32_t);
    ThiscallFn construct=(ThiscallFn)pool.constructor;
    factory->avail=nullptr;
    factory->active=nullptr;
    factory->used=0;
    factory->max=pool.count;
    factory->array=objects;
    for(uint32_t i=0;i<pool.count;++i) {
        uint8_t* object=objects+i*pool.size;
        construct(object);
        uint8_t* head=factory->avail;
        if(head) {
            Prev(object)=Prev(head);
            Next(object)=head;
            Next(Prev(head))=object;
            Prev(head)=object;
        } else {
            Next(object)=object;
            Prev(object)=object;
            factory->avail=object;
        }
    }
    return true;
}

template<int I> void* __fastcall Allocate(Factory* factory,void*) {
    void* object=((ThiscallFn)g_allocate[I])(factory);
    if(!object && !g_reported[I]) {
        g_reported[I]=true;
        lprintf("Vint %s pool is full (%u objects); UI elements are being dropped. Raise [VINT] %s.",
            g_pools[I].name,factory->max,g_pools[I].key);
    }
    return object;
}

bool (__cdecl* const kInit[kPoolCount])()={&InitPool<0>,&InitPool<1>,&InitPool<2>,&InitPool<3>};
void* (__fastcall* const kAllocate[kPoolCount])(Factory*,void*)={&Allocate<0>,&Allocate<1>,&Allocate<2>,&Allocate<3>};

bool Matches(const Pool& pool) {
    const uint8_t* code=(const uint8_t*)pool.init;
    if(code[0]!=0x56 || code[1]!=0x8B || code[2]!=0x35) return false;
    // mov eax,count / mov edx,size feed the native allocation size.
    if(code[0x1E]!=0xB8 || Read32(code+0x1F)!=pool.vanilla || code[0x23]!=0xBA || Read32(code+0x24)!=pool.size) return false;
    if(code[0x4F]!=0x68 || Read32(code+0x50)!=pool.constructor) return false;
    const Factory* factory=(const Factory*)pool.factory;
    if(factory->array || !factory->vtable) return false;
    return factory->vtable[1]==pool.allocate;
}

uint32_t ReadCount(CIniReader& ini,const Pool& pool) {
    const int value=ini.ReadInteger("VINT",pool.key,(int)pool.fallback);
    if(value<=(int)pool.vanilla) return pool.vanilla;
    if((uint32_t)value>kHardMax) return kHardMax;
    return (uint32_t)value;
}
}

void Install(CIniReader& ini) {
    for(int i=0;i<kPoolCount;++i) {
        Pool& pool=g_pools[i];
        pool.count=pool.vanilla;
        if(!Matches(pool)) {
            lprintf("Vint %s pool: unexpected code or factory state; left unchanged.",pool.name);
            continue;
        }
        uintptr_t* slot=((Factory*)pool.factory)->vtable+1;
        g_allocate[i]=*slot;
        Memory::VP::Patch<uintptr_t>((uintptr_t)slot,(uintptr_t)kAllocate[i]);
        const uint32_t wanted=ReadCount(ini,pool);
        if(wanted==pool.vanilla) continue;
        g_init_hooks[i]=safetyhook::create_inline((void*)pool.init,(void*)kInit[i]);
        if(!g_init_hooks[i]) {
            lprintf("Vint %s pool: could not hook the factory init; keeping vanilla %u.",pool.name,pool.vanilla);
            continue;
        }
        pool.count=wanted;
    }
    lprintf("Vint object pools: bitmap %u -> %u, group %u -> %u, text %u -> %u, bitmap_circle %u -> %u",
        g_pools[0].vanilla,g_pools[0].count,g_pools[1].vanilla,g_pools[1].count,
        g_pools[2].vanilla,g_pools[2].count,g_pools[3].vanilla,g_pools[3].count);
}
}
