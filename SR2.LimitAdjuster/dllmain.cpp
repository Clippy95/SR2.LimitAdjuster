// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include <safetyhook.hpp>
#include "sr_xml.h"
#include "ExtendedSaves.h"
#include "IniReader.h"
struct vector
{
    float x;
    float y;
    float z;
};

struct timestamp
{
    int value = -1;
};

SAFETYHOOK_NOINLINE void xtbl_free()
{
    auto xtbl = *(void**)0xE87138;
    auto id = *(int*)0xE87134;

    if (!xtbl)
        return;

    auto vft = *(void***)xtbl;

    auto fn = (void(__thiscall*)(void*, int))vft[0x34 / 4];

    fn(xtbl, id);

    *(int*)0xE87134 = -1;
}

struct checksum_stri
{
    unsigned int checksum = -1;
};


static std::mutex g_LogMutex;
static std::vector<std::string> g_DebugLogLines;
static bool g_DebugLogFlushed = false;

static std::filesystem::path GetDebugLogPath()
{
    char exe_path[MAX_PATH]{};
    DWORD length = GetModuleFileNameA(nullptr, exe_path, MAX_PATH);

    if (length > 0 && length < MAX_PATH)
    {
        std::filesystem::path path(exe_path);
        return path.parent_path() / "sr2_limitadjuster.txt";
    }

    return std::filesystem::path("sr2_limitadjuster.txt");
}

void lprintf(const char* format, ...)
{
    if (!format)
        return;

    char message[4096]{};

    va_list args;
    va_start(args, format);
    vsnprintf(message, sizeof(message), format, args);
    va_end(args);

    std::string full_message = "[SR2 Limit Adjuster] ";
    full_message += message;

    fputs(full_message.c_str(), stdout);
    fflush(stdout);

    std::lock_guard lock(g_LogMutex);
    g_DebugLogLines.push_back(std::move(full_message));
}

void FlushDebugLog()
{
    std::lock_guard lock(g_LogMutex);

    if (g_DebugLogFlushed || g_DebugLogLines.empty())
        return;

    std::ofstream file(GetDebugLogPath(), std::ios::out | std::ios::trunc | std::ios::binary);
    if (!file.is_open())
        return;

    for (const auto& line : g_DebugLogLines)
        file << line;

    g_DebugLogFlushed = true;
}

namespace CLimitAdjuster
{
    struct Options
    {
        unsigned __int8 force_dyn : 1;

    } AdjusterOptions;
    struct addr_xref {
        uintptr_t patch_location;  // Exact address of the 4-byte operand to patch
        size_t offset;             // Offset from new base
    };

    addr_xref customization_item_items_xrefs[] = {
        { 0x0053FD41, 0x0000 },  // lea     edi, Items.prev[ecx*8]; a1 -> 0x029E8CD0
        { 0x006109C5, 0x0000 },  // lea     ebx, Items.prev[ecx*8] -> 0x029E8CD0
        { 0x00611898, 0x0000 },  // lea     esi, Items.prev[edx*8] -> 0x029E8CD0
        { 0x00640F5C, 0x0000 },  // lea     eax, Items.prev[edx*8] -> 0x029E8CD0
        { 0x006BB709, 0x0000 },  // lea     esi, Items.prev[ecx*8] -> 0x029E8CD0
        { 0x007BBAE1, 0x0000 },  // lea     ebx, Items.prev[edx*8] -> 0x029E8CD0
        { 0x007BCDB7, 0x0000 },  // lea     eax, Items.prev[ecx*8] -> 0x029E8CD0
        { 0x007BD67B, 0x0000 },  // lea     eax, Items.prev[ecx*8] -> 0x029E8CD0
        { 0x007BDBF5, 0x0000 },  // lea     eax, Items.prev[edx*8] -> 0x029E8CD0
        { 0x007BE789, 0x0000 },  // lea     eax, Items.prev[ecx*8] -> 0x029E8CD0
        { 0x007C1A4B, 0x0000 },  // mov     eax, offset Items -> 0x029E8CD0
        { 0x007C1A86, 0x0000 },  // lea     eax, Items.prev[ecx*8] -> 0x029E8CD0
        { 0x007C1AAD, 0x0000 },  // lea     eax, Items.prev[ecx*8] -> 0x029E8CD0
        { 0x007C272C, 0x0000 },  // mov     edi, offset Items -> 0x029E8CD0
        { 0x007C2CE6, 0x0000 },  // mov     edi, offset Items -> 0x029E8CD0
        { 0x007C354F, 0x0000 },  // mov     edx, offset Items -> 0x029E8CD0
        { 0x007C3BAF, 0x0000 },  // mov     esi, offset Items -> 0x029E8CD0
        { 0x007C3E45, 0x0000 },  // mov     ecx, offset Items -> 0x029E8CD0
        { 0x007C3FA0, 0x0000 },  // mov     esi, offset Items -> 0x029E8CD0
        { 0x007C5885, 0x0000 },  // lea     eax, Items.prev[ecx*8] -> 0x029E8CD0
        { 0x007C5891, 0x0000 },  // cmp     eax, offset Items -> 0x029E8CD0
        { 0x007C58A7, 0x0000 },  // lea     ecx, Items.prev[edx*8] -> 0x029E8CD0
        { 0x007C58B0, 0x0000 },  // sub     eax, offset Items -> 0x029E8CD0
        { 0x007C6E97, 0x0000 },  // mov     [esp+2Ch+var_18], offset Items -> 0x029E8CD0
        { 0x007C715F, 0x0000 },  // lea     edi, Items.prev[ecx*8] -> 0x029E8CD0
        { 0x007C7366, 0x0000 },  // mov     esi, offset Items -> 0x029E8CD0
        { 0x007C74D6, 0x0000 },  // mov     esi, offset Items -> 0x029E8CD0
        { 0x007C8E2C, 0x0000 },  // lea     eax, Items.prev[edx*8] -> 0x029E8CD0
        { 0x007C8E6F, 0x0000 },  // cmp     eax, offset Items -> 0x029E8CD0
        { 0x007C8E7F, 0x0000 },  // lea     edx, Items.prev[edx*8] -> 0x029E8CD0
        { 0x007C8E88, 0x0000 },  // sub     eax, offset Items -> 0x029E8CD0
        { 0x007CA32D, 0x0000 },  // mov     ecx, offset Items -> 0x029E8CD0
        { 0x007CA7C6, 0x0000 },  // lea     eax, Items.prev[ecx*8] -> 0x029E8CD0
        { 0x007CA9CE, 0x0000 },  // lea     ecx, Items.prev[ecx*8] -> 0x029E8CD0
        { 0x007CB2D3, 0x0000 },  // lea     ecx, Items.prev[ecx*8] -> 0x029E8CD0
        { 0x007CB985, 0x0000 },  // lea     edx, Items.prev[edx*8] -> 0x029E8CD0
        { 0x007CC45C, 0x0000 },  // lea     ebx, Items.prev[edx*8] -> 0x029E8CD0
        { 0x007CC826, 0x0000 },  // lea     eax, Items.prev[eax*8] -> 0x029E8CD0
        { 0x007CC865, 0x0000 },  // cmp     eax, offset Items -> 0x029E8CD0
        { 0x007CC87B, 0x0000 },  // lea     ecx, Items.prev[edx*8] -> 0x029E8CD0
        { 0x007CC884, 0x0000 },  // sub     eax, offset Items -> 0x029E8CD0
        { 0x007D43EA, 0x0000 },  // lea     eax, Items.prev[ecx*8] -> 0x029E8CD0
        { 0x007D45CD, 0x0000 },  // lea     eax, Items.prev[ecx*8] -> 0x029E8CD0
        { 0x007D641E, 0x0000 },  // mov     ebp, offset Items -> 0x029E8CD0
        { 0x0081ABF0, 0x0000 },  // mov     eax, offset Items -> 0x029E8CD0
        { 0x0081ADB9, 0x0000 },  // lea     eax, Items.prev[edx*8] -> 0x029E8CD0
        { 0x0081B1B2, 0x0000 },  // lea     eax, Items.prev[edx*8] -> 0x029E8CD0
        { 0x0081B8BD, 0x0000 },  // lea     ebx, Items.prev[ecx*8] -> 0x029E8CD0
        { 0x0081C18B, 0x0000 },  // mov     esi, offset Items -> 0x029E8CD0
        { 0x0081C6AA, 0x0000 },  // mov     eax, offset Items -> 0x029E8CD0
        { 0x0081CBD2, 0x0000 },  // mov     ebx, offset Items -> 0x029E8CD0
        { 0x0081D828, 0x0000 },  // mov     ecx, offset Items -> 0x029E8CD0
        { 0x0081E102, 0x0000 },  // mov     edi, offset Items -> 0x029E8CD0
        { 0x0088DE77, 0x0000 },  // lea     eax, Items.prev[ecx*8] -> 0x029E8CD0
        { 0x009A02FE, 0x0000 },  // lea     edx, Items.prev[ecx*8] -> 0x029E8CD0
        { 0x00DAB6AC, 0x0010 },  // mov     eax, offset Items.m_name_tag_crc -> 0x029E8CE0
    };

    const size_t customization_item_items_xref_count = sizeof(customization_item_items_xrefs) / sizeof(customization_item_items_xrefs[0]);


    void patch_customization_item_items_references(void* new_base) {
        for (size_t i = 0; i < customization_item_items_xref_count; i++) {
            void* patch_addr = (void*)customization_item_items_xrefs[i].patch_location;
            void* new_value = (void*)((uintptr_t)new_base + customization_item_items_xrefs[i].offset);

            Memory::VP::Patch<void*>(patch_addr, new_value);
            printf("Patched 0x%p -> 0x%p (offset +0x%zX)\n",
                patch_addr, new_value, customization_item_items_xrefs[i].offset);
        }
    }

    addr_xref Obj_item_info_infos_xrefs[] = {
    { 0x004A3B0F, 0x0000 },  // mov     ecx, offset Obj_item_info -> 0x02BC5B00
    { 0x006E6BCB, 0x0000 },  // mov     edx, offset Obj_item_info -> 0x02BC5B00
    { 0x006EDF51, 0x0000 },  // mov     ecx, offset Obj_item_info -> 0x02BC5B00
    { 0x006EDFB0, 0x0000 },  // mov     ecx, offset Obj_item_info -> 0x02BC5B00
    { 0x0084391E, 0x0000 },  // mov     ecx, dword ptr Obj_item_info.name[edx] -> 0x02BC5B00
    { 0x008B3175, 0x0000 },  // mov     ecx, offset Obj_item_info -> 0x02BC5B00
    { 0x00925AA8, 0x005C },  // mov     eax, offset Obj_item_info.num_collectible_needed -> 0x02BC5B5C
    { 0x0092E8F4, 0x0000 },  // add     ebx, offset Obj_item_info -> 0x02BC5B00
    { 0x009302F7, 0x0008 },  // mov     ebp, offset Obj_item_info.mesh_name -> 0x02BC5B08
    { 0x009304C0, 0x0000 },  // mov     ecx, offset Obj_item_info -> 0x02BC5B00
    { 0x00930506, 0x0000 },  // mov     ecx, offset Obj_item_info -> 0x02BC5B00
    { 0x009305BD, 0x005C },  // mov     eax, offset Obj_item_info.num_collectible_needed -> 0x02BC5B5C
    { 0x00931079, 0x0000 },  // mov     eax, offset Obj_item_info -> 0x02BC5B00
    { 0x009310AC, 0x0000 },  // mov     eax, offset Obj_item_info -> 0x02BC5B00
    { 0x009310EF, 0x0004 },  // mov     ecx, offset Obj_item_info.name_checksum -> 0x02BC5B04
    { 0x00933F4B, 0x005C },  // mov     eax, offset Obj_item_info.num_collectible_needed -> 0x02BC5B5C
    { 0x00986597, 0x0000 },  // mov     ecx, offset Obj_item_info -> 0x02BC5B00
    { 0x009A35FB, 0x0000 },  // sub     ecx, offset Obj_item_info -> 0x02BC5B00
    { 0x009D09A1, 0x0000 },  // add     ecx, offset Obj_item_info -> 0x02BC5B00
    { 0x009F332F, 0x0000 },  // mov     ecx, offset Obj_item_info -> 0x02BC5B00
    { 0x00A542FD, 0x0000 },  // mov     ecx, offset Obj_item_info -> 0x02BC5B00
    { 0x00A54470, 0x0000 },  // mov     ecx, offset Obj_item_info -> 0x02BC5B00
    { 0x00A5994C, 0x0000 },  // mov     esi, offset Obj_item_info -> 0x02BC5B00
    { 0x00A61020, 0x0004 },  // mov     ecx, offset Obj_item_info.name_checksum -> 0x02BC5B04
    { 0x00A7E411, 0x0000 },  // mov     ecx, offset Obj_item_info -> 0x02BC5B00
    { 0x00A8239F, 0x0000 },  // mov     ecx, offset Obj_item_info -> 0x02BC5B00
    { 0x00A82440, 0x0000 },  // mov     ecx, offset Obj_item_info -> 0x02BC5B00
    { 0x00DAFC5C, 0x0054 },  // mov     eax, offset Obj_item_info.next_pickup_time -> 0x02BC5B54
    };

    const size_t Obj_item_info_infos_xref_count = sizeof(Obj_item_info_infos_xrefs) / sizeof(Obj_item_info_infos_xrefs[0]);


    void patch_Obj_item_info_infos_references(void* new_base) {
        for (size_t i = 0; i < Obj_item_info_infos_xref_count; i++) {
            void* patch_addr = (void*)Obj_item_info_infos_xrefs[i].patch_location;
            void* new_value = (void*)((uintptr_t)new_base + Obj_item_info_infos_xrefs[i].offset);

            Memory::VP::Patch<void*>(patch_addr, new_value);
            printf("Patched 0x%p -> 0x%p (offset +0x%zX)\n",
                patch_addr, new_value, Obj_item_info_infos_xrefs[i].offset);
        }
    }

    SafetyHookInline customize_item_system_initD;
    uint32_t items_count = 0;

    uint32_t get_bytes(uint32_t count, uint32_t char_length)
    {
        return count * char_length;
    }
     
    struct customization_item
    {
        customization_item* prev;
        customization_item* next;
        const char* name;
        const wchar_t* m_display_name;
        checksum_stri m_name_tag_crc;
        char pad[100];
    };

    struct  object_item_info
    {
        char* name;
        checksum_stri name_checksum;
        char* mesh_name;
        bool preloaded;
        bool large_prop;
        bool no_anim_prop_attach;
        const wchar_t* display_name;
        void* mesh;
        int primary_handle_tag_index;
        float mass;
        float linear_damping;
        float angular_damping;
        float restitution;
        float friction;
        vector angular_velocity;
        int respawn_delay;
        float render_scale;
        bool scale_ambient;
        void* function;
        int flags;
        unsigned __int16 m_pickup_snd_id;
        unsigned __int16 m_foley_collision_id;
        timestamp next_pickup_time;
        timestamp next_coll_time;
        int num_collectible_needed;
        int num_collectible_gotten;
        int collectible_index;
        int glow_type;
        int m_num_lods;
        float m_lod_info[4];
        int wieldable_type;
        float wieldable_damage;
        int m_num_color_variant_groups;
        void* m_color_variant_groups;
    };


     void* SAFETYHOOK_CCALL customize_item_system_init()
    {
         auto items = xtbl_parse_table_node("customization_items.xtbl", (void*)0x0277307C_g);
         items_count = xml_count(items, "Customization_Item");
         xtbl_free();
         if (AdjusterOptions.force_dyn || items_count > 1050) {
             Patch<uint32_t>(0x7BF7D1 + 1, get_bytes(items_count, 32));
             Patch<uint32_t>(0x7BF7D1 + 1, get_bytes(items_count, 32));
             Patch<uint32_t>(0x7BF83E + 6, items_count);
             Patch<uint32_t>(0x7BF832 + 1, items_count * 4);
             Patch<uint32_t>(0x7BBAC6 + 1, items_count);
             Patch<uint32_t>(0x7BCC14 + 6, items_count);
             
             auto new_items = new customization_item[items_count];
             lprintf("Patching customization_items with %p count is %d\n", new_items, items_count);
             patch_customization_item_items_references(new_items);
         }
        return customize_item_system_initD.unsafe_ccall<void*>();


    }
     SafetyHookInline sr2_init_stage_1D;
     char _cdecl sr2_init_stage_1_hook()
     {

         Patch<uint32_t>(0x51EE12 + 1, 737280 * 2);
         Patch<uint32_t>(0x51EE50 + 1, 737280 * 2);



         return sr2_init_stage_1D.unsafe_ccall<char>();
     }
     SafetyHookInline sr2_init_stage_2D;
     int _cdecl sr2_init_stage_2_hook()
     {
         auto object_info = xtbl_parse_table_node("items_3d.xtbl", nullptr);
         auto object_info_count = xml_count(object_info, "Item");
         if (AdjusterOptions.force_dyn || object_info_count > 219) {
             auto new_obj_items = new object_item_info[object_info_count];
             lprintf("Patching items_3d with %p count is %d\n", new_obj_items, object_info_count);
             patch_Obj_item_info_infos_references(new_obj_items);
         }
         xtbl_free();
         return sr2_init_stage_2D.unsafe_ccall<int>();
     }

     struct MySaveData
     {
         int weapon_limit;
         int owned_weapon_cap;
     };

     MySaveData data{
    2048,
    4096
     };

     static void OnBeforeSave(const char* save_name)
     {
         ExtendedSaves::SetPod("limitadjuster_state", data);
         lprintf("OnBeforeSave %s count=%u ext=0x%X\n",
             save_name ? save_name : "<null>",
             ExtendedSaves::GetCurrentChunkCount(),
             ExtendedSaves::GetSerializedExtensionSize());
     }

    void Init()
    {
        CIniReader ini{};
        AdjusterOptions.force_dyn = ini.ReadInteger("MAIN", "ForceEvenIfBelow", true) != 0;
        ExtendedSaves::InstallHooks();
        //ExtendedSaves::RegisterBeforeSaveCallback(OnBeforeSave);
        static auto testing = safetyhook::create_mid(0x7BBA68_g, [](SafetyHookContext& ctx) {
            xml_element* node = (xml_element*)ctx.eax;
            });
        customize_item_system_initD = safetyhook::create_inline(0x7BF790_g, customize_item_system_init);
        sr2_init_stage_1D = safetyhook::create_inline(0x51D800, sr2_init_stage_1_hook);
        sr2_init_stage_2D = safetyhook::create_inline(0x51F700, sr2_init_stage_2_hook);

        static auto game_shutdown = safetyhook::create_mid(0x699BC0_g, [](SafetyHookContext& ctx) {
            FlushDebugLog();
            });
    }
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    {
        CLimitAdjuster::Init();
    }
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        FlushDebugLog();
        break;
    }
    return TRUE;
}

