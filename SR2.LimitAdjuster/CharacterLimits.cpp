#include "pch.h"
#include "CharacterLimits.h"
#include "sr_xml.h"
#include <safetyhook.hpp>
#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <limits>
#include <memory>
#include <string>
#include <vector>
#include <unordered_set>

extern void lprintf(const char*, ...);
extern void xtbl_free();

namespace CharacterLimits {
namespace {
const uintptr_t kRetailPresets = 0x25F9C48_g;
constexpr uint32_t kVanillaPresets = 1000;
constexpr uint32_t kMaxPresets = 65535; // Native hash free-list indices are uint16.
struct Preset { const char* name; uint32_t hash; std::array<std::byte,64> rest; };
struct HashNode { Preset* value; HashNode* next; HashNode* previous; uint32_t hash; int bucket; };
struct Links { uint16_t next,previous; };
static_assert(sizeof(Preset)==72 && sizeof(HashNode)==20 && sizeof(Links)==4);
std::vector<Preset> g_presets;
std::vector<HashNode> g_hash_nodes;
std::vector<HashNode*> g_buckets;
std::vector<Links> g_links;
std::vector<uint8_t> g_generations;
uint32_t g_capacity=0;
bool g_dlc_loaded=false;
std::unordered_set<std::string> g_strings;
const char* __stdcall StoreString(const char* value) {
    return g_strings.emplace(value).first->c_str();
}
SafetyHookInline g_split_hook,g_presets_hook,g_menu_hook;
SafetyHookInline g_morph_init_hook,g_morph_parse_hook,g_post_load_hook;
struct CharacterPostLoad { uintptr_t vtable; uint32_t resource; void* anim_set; void* rig; };
static_assert(sizeof(CharacterPostLoad)==16);
std::vector<CharacterPostLoad> g_post_load;
struct MorphPair {
    MorphPair* next;
    MorphPair* previous;
    uint32_t model_hash,morph_hash;
    char model[64],morph[64];
};
static_assert(sizeof(MorphPair)==144 && offsetof(MorphPair,model)==16 && offsetof(MorphPair,morph)==80);
constexpr size_t kMorphBlockSize=256;
using MorphBlock=std::array<MorphPair,kMorphBlockSize>;
std::vector<std::unique_ptr<MorphBlock>> g_morph_blocks;
size_t g_morph_blocks_used=0;
using ParseEntry=void(__cdecl*)(xml_element*,int);
using AllocateEntries=void(__cdecl*)(int,int);
using SplitAbi=uc::abi<uc::eax_ret<void*>,uc::ecx_arg<const char*>,uc::edx_arg<ParseEntry>,uc::stack_arg<const char*>,uc::stack_arg<AllocateEntries>,uc::stack_arg<int>>;
SplitAbi::callback_t g_split_callback;

[[noreturn]] void Fail(const char* message) {
    lprintf("Character limits: %s",message);
    FatalAppExitA(0,message);
    std::terminate();
}
void __cdecl PrepareCharacterPostLoad() {
    const auto count=*reinterpret_cast<uint32_t*>(0xF5BB68_g);
    const auto old_count=g_post_load.size();
    g_post_load.resize(count);
    for(size_t i=old_count;i<g_post_load.size();++i)
        g_post_load[i]={0xDDA82C_g,0,nullptr,nullptr};
    const auto base=reinterpret_cast<uintptr_t>(g_post_load.data());
    Memory::VP::Patch<uintptr_t>(0x4A4071_g,base+8);
    Memory::VP::Patch<uintptr_t>(0x4A412C_g,base);
    g_post_load_hook.call<void>();
    lprintf("Character streaming callbacks: %u records (vanilla 800)",count);
}
void* __cdecl InitializeMorphs() {
    g_morph_blocks_used=0;
    return g_morph_init_hook.call<void*>();
}
void __cdecl ParseMorphPair(xml_element* entry) {
    auto& free_head=*reinterpret_cast<MorphPair**>(0x2527D58_g);
    if(!free_head) {
        if(g_morph_blocks_used==g_morph_blocks.size()) {
            try { g_morph_blocks.push_back(std::make_unique<MorphBlock>()); }
            catch(const std::bad_alloc&) { Fail("Could not allocate additional character morph-pair records."); }
        }
        auto& block=*g_morph_blocks[g_morph_blocks_used];
        for(size_t i=0;i<block.size();++i) {
            block[i]={};
            block[i].next=&block[(i+1)%block.size()];
            block[i].previous=&block[(i+block.size()-1)%block.size()];
        }
        free_head=block.data();
        ++g_morph_blocks_used;
        lprintf("Character morph pairs: capacity grew to %u records (vanilla 512)",
            static_cast<unsigned>(512+g_morph_blocks_used*kMorphBlockSize));
    }
    g_morph_parse_hook.call<void>(entry);
}
void FreeTable() {
    if (*reinterpret_cast<int*>(0xE87134_g)>=0) xtbl_free();
}
std::vector<std::string> ReadNames(const char* filename,const char* entry,const char* suffix,AllocateEntries allocation=nullptr,int context=0) {
    std::vector<std::string> files;
    auto table=xtbl_parse_table_node(filename,nullptr);
    for(auto node=xtbl_find(table,entry);node;node=xtbl_find_next(table,node,entry)) {
        const auto name=xtbl_get_req_string_ref(node,"Name");
        if(!name || !*name) Fail("Character registry contains an unnamed entry.");
        files.emplace_back(std::string(name)+"_"+suffix+".xtbl");
    }
    // Preserve the original callback timing: XML remains valid here.
    if(allocation) allocation(static_cast<int>(files.size()),context);
    FreeTable();
    return files;
}
void* __cdecl LoadSplit(const char* suffix,ParseEntry parse,const char* filename,AllocateEntries allocate,int context) {
    const auto files=ReadNames(filename,"Character",suffix,allocate,context);
    for(const auto& file:files) {
        auto table=xtbl_parse_table_node(file.c_str(),nullptr);
        if(auto entry=xtbl_find(table,"Character")) parse(entry,context);
        FreeTable();
    }
    return nullptr;
}
void PatchPresetBase() {
    // LEA EBP,[EBP*8+base], MOV ESI,base+32 and MOV ECX,base.
    // The constructor at DA50AB executes before table loading and stays native.
    Memory::VP::Patch<uintptr_t>(0x4A537E_g,reinterpret_cast<uintptr_t>(g_presets.data()));
    Memory::VP::Patch<uintptr_t>(0x4A4EE6_g,reinterpret_cast<uintptr_t>(g_presets.data())+32);
    Memory::VP::Patch<uintptr_t>(0x4A5D1F_g,reinterpret_cast<uintptr_t>(g_presets.data()));
}
void ResetStorage(uint32_t required) {
    if(required>kMaxPresets) Fail("Character preset count exceeds the native 16-bit hash index range.");
    const uint32_t capacity=(std::max)(required,kVanillaPresets);
    g_strings.clear();
    g_presets.assign(capacity,{});
    for(auto& preset:g_presets) preset.hash=0xFFFFFFFF;
    g_hash_nodes.assign(capacity,{});g_buckets.assign(capacity,nullptr);
    g_links.resize(capacity);g_generations.assign(capacity,0xFF);
    // Same circular free list built by retail 4A6150/4A6290.
    for(uint32_t i=0;i<capacity;++i) {
        g_links[i].next=static_cast<uint16_t>(i?i-1:capacity-1);
        g_links[i].previous=static_cast<uint16_t>(i+1==capacity?0:i+1);
    }
    *reinterpret_cast<HashNode**>(0x260B5E8_g)=g_hash_nodes.data();
    *reinterpret_cast<Links**>(0x260B5EC_g)=g_links.data();
    *reinterpret_cast<uint8_t**>(0x260B5F0_g)=g_generations.data();
    *reinterpret_cast<uint32_t*>(0x260B5FC_g)=capacity;
    *reinterpret_cast<uint32_t*>(0x260B600_g)=0;
    *reinterpret_cast<uint32_t*>(0x260B604_g)=capacity;
    *reinterpret_cast<uint32_t*>(0x260B60C_g)=0;
    *reinterpret_cast<uint32_t*>(0x260B610_g)=0;
    *reinterpret_cast<HashNode***>(0x260B644_g)=g_buckets.data();
    *reinterpret_cast<uint32_t*>(0x260B648_g)=capacity;
    g_capacity=capacity;PatchPresetBase();
    lprintf("Character presets: %u detected; %u records and hash nodes allocated (vanilla %u)",required,capacity,kVanillaPresets);
}
void ParsePresets(const std::vector<std::string>& files) {
    for(const auto& file:files) {
        auto table=xtbl_parse_table_node(file.c_str(),nullptr);
        if(auto preset=xtbl_find(table,"Preset")) {
            if(*reinterpret_cast<uint32_t*>(0x2526C60_g)>=g_capacity) Fail("Character preset storage exhausted before parsing an entry.");
            reinterpret_cast<void(__cdecl*)(xml_element*)>(0x4A5320_g)(preset);
        }
        FreeTable();
    }
}
void* __cdecl LoadPresets() {
    auto& count=*reinterpret_cast<uint32_t*>(0x2526C60_g);
    if(!count) {
        auto base=ReadNames("character_presets.xtbl","Preset","pre");
        auto dlc=ReadNames("dlc_character_presets.xtbl","Preset","pre");
        ResetStorage(static_cast<uint32_t>(base.size()+dlc.size()));
        g_dlc_loaded=false;ParsePresets(base);
    } else if(!g_dlc_loaded) {
        auto dlc=ReadNames("dlc_character_presets.xtbl","Preset","pre");
        if(dlc.size()>g_capacity-count) Fail("DLC preset registry changed after capacity was measured.");
        ParsePresets(dlc);g_dlc_loaded=true;
    }
    return nullptr;
}
Preset* __cdecl SelectPreset() {
    const auto count=*reinterpret_cast<uint32_t*>(0x2526C60_g);
    if(count>g_capacity) Fail("Invalid character preset count in selector.");
    std::vector<const char*> names;names.reserve(count);
    for(uint32_t i=0;i<count;++i) if(g_presets[i].name) names.push_back(g_presets[i].name);
    std::sort(names.begin(),names.end(),[](const char* a,const char* b){return std::strcmp(a,b)<0;});
    static auto menu=uc::make<uc::eax_ret<int>,uc::eax_arg<const char**>,uc::stack_arg<const char*>,uc::stack_arg<int>,uc::stack_arg<int>>(0x759120_g);
    const int selected=menu(names.data(),"Select a human to drop",static_cast<int>(names.size()),0);
    if(selected<0 || static_cast<size_t>(selected)>=names.size()) return nullptr;
    for(uint32_t i=0;i<count;++i) if(g_presets[i].name==names[selected]) return &g_presets[i];
    return nullptr;
}
}
void Install() {
    // Reject a conflicting relocation instead of blindly patching its address.
    if(*reinterpret_cast<uintptr_t*>(0x4A537E_g)!=kRetailPresets ||
       *reinterpret_cast<uintptr_t*>(0x4A4EE6_g)!=kRetailPresets+32 ||
       *reinterpret_cast<uintptr_t*>(0x4A5D1F_g)!=kRetailPresets)
        Fail("Character preset operands differ from the supported SR2 executable.");
    for(const auto site:{0x4A53B5_g,0x4A5493_g}) {
        if(*reinterpret_cast<const uint8_t*>(site)!=0xE8 ||
           site+5+*reinterpret_cast<const int32_t*>(site+1)!=0xC06D60_g)
            Fail("Character preset string call differs from the supported executable.");
    }
    constexpr uint8_t morph_parser_start[]={0x81,0xEC,0x8C,0x00,0x00,0x00};
    constexpr uint8_t morph_init_start[]={0x51,0x8B,0x15};
    if(std::memcmp(reinterpret_cast<const void*>(0x6DFD80_g),morph_parser_start,sizeof(morph_parser_start)) ||
       std::memcmp(reinterpret_cast<const void*>(0x6E0640_g),morph_init_start,sizeof(morph_init_start)) ||
       *reinterpret_cast<const uintptr_t*>(0x6E0643_g)!=0x33D630C_g)
        Fail("Character morph registry entry points differ from the supported executable.");
    if(*reinterpret_cast<const uintptr_t*>(0x4A4071_g)!=0x25F69F0_g ||
       *reinterpret_cast<const uintptr_t*>(0x4A412C_g)!=0x25F69E8_g)
        Fail("Character streaming callback operands differ from the supported executable.");
    g_post_load_hook=safetyhook::create_inline(0x4A4060_g,PrepareCharacterPostLoad);
    if(!g_post_load_hook) Fail("Could not install character streaming callback capacity hook.");
    g_morph_parse_hook=safetyhook::create_inline(0x6DFD80_g,ParseMorphPair);
    g_morph_init_hook=safetyhook::create_inline(0x6E0640_g,InitializeMorphs);
    if(!g_morph_parse_hook || !g_morph_init_hook) Fail("Could not install character morph-pair growth hooks.");
    uc::patch_call(0x4A53B5_g,StoreString);
    uc::patch_call(0x4A5493_g,StoreString);
    g_split_callback=SplitAbi::make_callback(LoadSplit);
    g_split_hook=safetyhook::create_inline(0x4A4870_g,g_split_callback.raw());
    g_presets_hook=safetyhook::create_inline(0x4A5DE0_g,LoadPresets);
    g_menu_hook=safetyhook::create_inline(0x4A5C50_g,SelectPreset);
    if(!g_split_hook || !g_presets_hook || !g_menu_hook) Fail("Could not install character registry capacity hooks.");
    lprintf("Character registry filename lists are dynamic; preset storage follows the loaded registry count.");
}
}
