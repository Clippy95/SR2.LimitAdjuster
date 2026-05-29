// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include <safetyhook.hpp>
#include "BuildVersion.h"
#include "sr_xml.h"
#include "ExtendedSaves.h"
#include "LimitConfig.h"
#include "Mempool.h"
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
static bool g_DebugLogInitialized = false;

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

static std::string BuildLogPrefix()
{
    SYSTEMTIME local_time{};
    GetLocalTime(&local_time);

    char prefix[128]{};
    snprintf(
        prefix,
        sizeof(prefix),
        "[%04u-%02u-%02u %02u:%02u:%02u.%03u][T%lu][SR2 Limit Adjuster] ",
        local_time.wYear,
        local_time.wMonth,
        local_time.wDay,
        local_time.wHour,
        local_time.wMinute,
        local_time.wSecond,
        local_time.wMilliseconds,
        GetCurrentThreadId());

    return prefix;
}

static void AppendDebugLogLineLocked(const std::string& line)
{
    const auto path = GetDebugLogPath();
    const auto open_mode = std::ios::out | std::ios::binary | (g_DebugLogInitialized ? std::ios::app : std::ios::trunc);

    std::ofstream file(path, open_mode);
    if (!file.is_open())
        return;

    file.write(line.data(), static_cast<std::streamsize>(line.size()));
    file.flush();
    g_DebugLogInitialized = true;
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

    std::string full_message = BuildLogPrefix();
    full_message += message;
    if (full_message.empty() || full_message.back() != '\n')
        full_message.push_back('\n');

    fputs(full_message.c_str(), stdout);
    fflush(stdout);

    std::lock_guard lock(g_LogMutex);
    AppendDebugLogLineLocked(full_message);
}

void FlushDebugLog()
{
    std::lock_guard lock(g_LogMutex);
    fflush(stdout);
}

namespace CLimitAdjuster
{
    struct Options
    {
        unsigned __int8 force_dyn : 1;
        CountSetting customization_items_limit;
        CountSetting items_3d_limit;
        CountSetting customization_logos_limit;

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
            //printf("Patched 0x%p -> 0x%p (offset +0x%zX)\n",
            //    patch_addr, new_value, customization_item_items_xrefs[i].offset);
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
            //printf("Patched 0x%p -> 0x%p (offset +0x%zX)\n",
            //    patch_addr, new_value, Obj_item_info_infos_xrefs[i].offset);
        }
    }

    addr_xref Logos_Array_xrefs[] = {
    { 0x007BD14E, 0x0004 },  // mov     ecx, offset Logos.m_name_checksum -> 0x02A0A7F4
    { 0x007BD19B, 0x0000 },  // lea     eax, Logos.m_name[eax*8] -> 0x02A0A7F0
    { 0x007BDF4E, 0x0000 },  // mov     [esp+74h+var_60], offset Logos -> 0x02A0A7F0
    { 0x007BE40A, 0x0004 },  // mov     ecx, offset Logos.m_name_checksum -> 0x02A0A7F4
    { 0x007BE429, 0x0000 },  // lea     eax, Logos.m_name[eax*8] -> 0x02A0A7F0
    { 0x007C029E, 0x0000 },  // cmp     eax, offset Logos -> 0x02A0A7F0
    { 0x007C02B1, 0x0000 },  // lea     ecx, Logos.m_name[ecx*8] -> 0x02A0A7F0
    { 0x007C02BA, 0x0000 },  // sub     eax, offset Logos -> 0x02A0A7F0
    { 0x007C10EA, 0x0000 },  // cmp     eax, offset Logos -> 0x02A0A7F0
    { 0x007C10FD, 0x0000 },  // lea     ecx, Logos.m_name[ecx*8] -> 0x02A0A7F0
    { 0x007C1106, 0x0000 },  // sub     eax, offset Logos -> 0x02A0A7F0
    { 0x007C2BE4, 0x0004 },  // mov     ecx, offset Logos.m_name_checksum -> 0x02A0A7F4
    { 0x007C2BFE, 0x0000 },  // lea     eax, Logos.m_name[eax*8] -> 0x02A0A7F0
    { 0x007C3612, 0x0004 },  // mov     ecx, offset Logos.m_name_checksum -> 0x02A0A7F4
    { 0x007C3668, 0x0000 },  // lea     eax, Logos.m_name[eax*8] -> 0x02A0A7F0
    { 0x007C3891, 0x0004 },  // mov     ecx, offset Logos.m_name_checksum -> 0x02A0A7F4
    { 0x007C38B7, 0x0000 },  // lea     eax, Logos.m_name[eax*8] -> 0x02A0A7F0
    { 0x007C4094, 0x0004 },  // mov     ecx, offset Logos.m_name_checksum -> 0x02A0A7F4
    { 0x007C40EC, 0x0000 },  // lea     eax, Logos.m_name[eax*8] -> 0x02A0A7F0
    { 0x007C40F5, 0x0000 },  // cmp     eax, offset Logos -> 0x02A0A7F0
    { 0x007C4102, 0x0000 },  // lea     edx, Logos.m_name[ecx*8] -> 0x02A0A7F0
    { 0x007C410B, 0x0000 },  // sub     eax, offset Logos -> 0x02A0A7F0
    { 0x007C4C98, 0x0000 },  // cmp     eax, offset Logos -> 0x02A0A7F0
    { 0x007C5288, 0x0004 },  // mov     ecx, offset Logos.m_name_checksum -> 0x02A0A7F4
    { 0x007C52A8, 0x0000 },  // lea     eax, Logos.m_name[eax*8] -> 0x02A0A7F0
    { 0x007C58D5, 0x0000 },  // cmp     eax, offset Logos -> 0x02A0A7F0
    { 0x007C58E8, 0x0000 },  // lea     edx, Logos.m_name[ecx*8] -> 0x02A0A7F0
    { 0x007C58F1, 0x0000 },  // sub     eax, offset Logos -> 0x02A0A7F0
    { 0x007C591A, 0x0000 },  // cmp     eax, offset Logos -> 0x02A0A7F0
    { 0x007C592D, 0x0000 },  // lea     edx, Logos.m_name[ecx*8] -> 0x02A0A7F0
    { 0x007C5936, 0x0000 },  // sub     eax, offset Logos -> 0x02A0A7F0
    { 0x007C5975, 0x0000 },  // lea     eax, Logos.m_name[eax*8] -> 0x02A0A7F0
    { 0x007C9FE1, 0x0000 },  // cmp     eax, offset Logos -> 0x02A0A7F0
    { 0x007C9FF4, 0x0000 },  // lea     ecx, Logos.m_name[ecx*8] -> 0x02A0A7F0
    { 0x007C9FFD, 0x0000 },  // sub     eax, offset Logos -> 0x02A0A7F0
    { 0x007CB03E, 0x0000 },  // cmp     ecx, offset Logos -> 0x02A0A7F0
    { 0x007CB050, 0x0000 },  // lea     eax, Logos.m_name[eax*8] -> 0x02A0A7F0
    { 0x007CB05C, 0x0000 },  // sub     edx, offset Logos -> 0x02A0A7F0
    { 0x007CC025, 0x0000 },  // lea     edx, Logos.m_name[edx*8] -> 0x02A0A7F0
    { 0x007CC066, 0x0000 },  // lea     eax, Logos.m_name[eax*8] -> 0x02A0A7F0
    { 0x00DAB70C, 0x000C },  // mov     eax, offset Logos.m_name_tag_crc -> 0x02A0A7FC
    };

    const size_t Logos_Array_xref_count = sizeof(Logos_Array_xrefs) / sizeof(Logos_Array_xrefs[0]);


    void patch_Logos_Array_references(void* new_base) {
        for (size_t i = 0; i < Logos_Array_xref_count; i++) {
            void* patch_addr = (void*)Logos_Array_xrefs[i].patch_location;
            void* new_value = (void*)((uintptr_t)new_base + Logos_Array_xrefs[i].offset);

            Memory::VP::Patch<void*>(patch_addr, new_value);
            //printf("Patched 0x%p -> 0x%p (offset +0x%zX)\n",
            //    patch_addr, new_value, Logos_Array_xrefs[i].offset);
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

    struct object_item_info
    {
        char* NAME;
        checksum_stri NAME_CRC;
        char* MESH_NAME;
        bool PRELOADED;
        bool LARGE_PROP;
        bool NO_ANIM_ATTACH;
        const wchar_t* DISPLAY_NAME;
        void* MESH;
        int HANDLE_TAG;
        float MASS;
        float LINEAR_DAMP;
        float ANGULAR_DAMP;
        float RESTITUTION;
        float FRICTION;
        vector ANGULAR_VEL;
        int RESPAWN_DELAY;
        float RENDER_SCALE;
        bool SCALE_AMBIENT;
        void* FUNC;
        int FLAGS;
        unsigned __int16 PICKUP_SND_ID;
        unsigned __int16 FOLEY_COLL_ID;
        timestamp NEXT_PICKUP_TIME;
        timestamp NEXT_COLL_TIME;
        int COLLECTIBLE_NEED;
        int COLLECTIBLE_HAVE;
        int COLLECTIBLE_INDEX;
        int GLOW_TYPE;
        int NUM_LODS;
        float LOD_INFO[4];
        int WIELD_TYPE;
        float WIELD_DAMAGE;
        int NUM_COLOR_GROUPS;
        void* COLOR_GROUPS;
    };

    struct customization_logo
    {
        char* NAME;
        checksum_stri NAME_CRC;
        const wchar_t* DISPLAY_NAME;
        checksum_stri NAME_TAG_CRC;
        checksum_stri IMAGE_CRC;
        char* PEG_NAME;
    };


     void* SAFETYHOOK_CCALL customize_item_system_init()
    {
         auto items = xtbl_parse_table_node("customization_items.xtbl", (void*)0x0277307C_g);
         auto dlc_items = xtbl_parse_table_node("dlc_customization_items.xtbl", (void*)0x0277307C_g);
         items_count = xml_count(items, "Customization_Item");

         if (dlc_items)
         {
             items_count += xml_count(dlc_items, "Customization_Item");
         }

         const auto items_capacity = resolve_capacity(
             "CustomizationItems",
             AdjusterOptions.customization_items_limit,
             items_count,
             kVanillaCustomizationItemsLimit);
         xtbl_free();
         if (should_apply_capacity_patch(
             AdjusterOptions.force_dyn,
             AdjusterOptions.customization_items_limit,
             items_capacity,
             kVanillaCustomizationItemsLimit)) {
             Patch<uint32_t>(0x7BF7D1 + 1, get_bytes(items_capacity, 32));
             Patch<uint32_t>(0x7BF7D1 + 1, get_bytes(items_capacity, 32));
             Patch<uint32_t>(0x7BF83E + 6, items_capacity);
             Patch<uint32_t>(0x7BF832 + 1, items_capacity * 4);
             Patch<uint32_t>(0x7BBAC6 + 1, items_capacity);
             Patch<uint32_t>(0x7BCC14 + 6, items_capacity);
             
             auto new_items = new customization_item[items_capacity];
             lprintf("Patching customization_items with %p count=%u capacity=%u\n", new_items, items_count, items_capacity);
             patch_customization_item_items_references(new_items);
          }
        return customize_item_system_initD.unsafe_ccall<void*>();


    }
     SafetyHookInline sr2_init_stage_1D;
     char _cdecl sr2_init_stage_1_hook()
     {
         CIniReader ini;
         if (ini.ReadInteger("EXPERIMENTAL", "DynamicMempools", 0) != 0)
         {
             Nop(0xC00E4A, 5);
         }
         Patch<uint32_t>(0x51EE12 + 1, 737280 * 2);
         Patch<uint32_t>(0x51EE50 + 1, 737280 * 2);



         return sr2_init_stage_1D.unsafe_ccall<char>();
     }
     SafetyHookInline sr2_init_stage_2D;
     int _cdecl sr2_init_stage_2_hook()
     {
          auto object_info = xtbl_parse_table_node("items_3d.xtbl", nullptr);
          auto object_info_count = xml_count(object_info, "Item");
          const auto object_info_capacity = resolve_capacity(
              "Items3D",
              AdjusterOptions.items_3d_limit,
              object_info_count,
              kVanillaItems3DLimit);
          if (should_apply_capacity_patch(
              AdjusterOptions.force_dyn,
              AdjusterOptions.items_3d_limit,
              object_info_capacity,
              kVanillaItems3DLimit)) {
              auto new_obj_items = new object_item_info[object_info_capacity];
              lprintf("Patching items_3d with %p count=%u capacity=%u\n", new_obj_items, object_info_count, object_info_capacity);
              patch_Obj_item_info_infos_references(new_obj_items);
          }




         auto root = xtbl_parse_table_node("anim_files.xtbl", nullptr);
         auto files = xml_find_child(root, "Files");
         auto anim_files = xml_find_child(files, "Anim_files");
         auto anim_files_count = xml_count_children(anim_files, "Anim_file");

         lprintf("retail anim_file count = %d\n", anim_files_count);



         auto root_logos = xtbl_parse_table_node("customization_logos.xtbl", nullptr);

          if (root_logos)
          {
              auto logos_count_wanted = xml_count(root_logos, "Logo");
              const auto logos_capacity = resolve_capacity(
                  "CustomizationLogos",
                  AdjusterOptions.customization_logos_limit,
                  logos_count_wanted,
                  kVanillaCustomizationLogosLimit,
                  kAutoCustomizationLogoHeadroom,
                  kMaxCustomizationLogoIndex);
              lprintf("customization_logos count %d\n", logos_count_wanted);

              if (should_apply_capacity_patch(
                  AdjusterOptions.force_dyn,
                  AdjusterOptions.customization_logos_limit,
                  logos_capacity,
                  kVanillaCustomizationLogosLimit))
              {
                  auto new_logos_array = new customization_logo[logos_capacity];
                  lprintf("Patching customization_logos with %p count=%u capacity=%u\n", new_logos_array, logos_count_wanted, logos_capacity);
                  patch_Logos_Array_references(new_logos_array);
              }

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

     SafetyHookInline character_initd;

     void* SAFETYHOOK_CCALL character_init()
     {
         xtbl_free();

         return character_initd.ccall<void*>();
     }

    void Init()
    {
        CIniReader ini{};
        lprintf("Build %s | rev %u | %s%s\n",
            BuildVersion::kBuildTimestamp,
            BuildVersion::kGitCommitCount,
            BuildVersion::kGitShortHash,
            BuildVersion::kGitDirty ? " dirty" : "");
        AdjusterOptions.force_dyn = ini.ReadInteger("MAIN", "ForceEvenIfBelow", true) != 0;
        AdjusterOptions.customization_items_limit = read_count_setting(
            ini, "LIMITS", "CustomizationItems", kVanillaCustomizationItemsLimit);
        AdjusterOptions.items_3d_limit = read_count_setting(
            ini, "LIMITS", "Items3D", kVanillaItems3DLimit);
        AdjusterOptions.customization_logos_limit = read_count_setting(
            ini, "LIMITS", "CustomizationLogos", kVanillaCustomizationLogosLimit);
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


            Mempool_init();
        
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
        DisableThreadLibraryCalls(hModule);
        CLimitAdjuster::Init();
        break;
    }
    case DLL_PROCESS_DETACH:
        FlushDebugLog();
        break;
    }
    return TRUE;
}

