// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include <safetyhook.hpp>
#include "BuildVersion.h"
#include "sr_xml.h"
#include "ExtendedSaves.h"
#include "LimitConfig.h"
#include "Mempool.h"
#include <unordered_map>
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
    int checksum = -1;
};

class __declspec(align(4)) bit_array
{
public:
    unsigned __int8* mem;
    unsigned int size;
    bool is_allocated;

    static bit_array from_storage(void* storage, unsigned int bytes)
    {
        return bit_array{
            static_cast<unsigned __int8*>(storage),
            bytes,
            false
        };
    }

    static bit_array from_bit_count(void* storage, unsigned int bit_count)
    {
        return from_storage(storage, (bit_count + 7u) / 8u);
    }

    unsigned int byte_count() const
    {
        return size;
    }

    unsigned int bit_capacity() const
    {
        return size * 8u;
    }

    bool has_bit(unsigned int bit_index) const
    {
        return mem && bit_index < bit_capacity();
    }

    bool set_bit(unsigned int bit_index)
    {
        if (!has_bit(bit_index))
            return false;

        mem[bit_index / 8u] |= static_cast<unsigned __int8>(1u << (bit_index % 8u));
        return true;
    }
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
        unsigned __int8 unlockables_save_ext_enabled : 1;
        unsigned __int8 weapon_infos_save_ext_enabled : 1;
        CountSetting customization_items_limit;
        CountSetting items_3d_limit;
        CountSetting customization_logos_limit;
        CountSetting unlockables_limit;
        uint32_t weapon_store_bucket_limit;

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

    addr_xref Unlockables_Array_xrefs[] = {
    { 0x0053A958, 0x0000 },  // mov     ecx, offset Unlockables -> 0x027DD018
    { 0x00605B0F, 0x0000 },  // mov     eax, offset Unlockables -> 0x027DD018
    { 0x00605B42, 0x0000 },  // mov     eax, offset Unlockables -> 0x027DD018
    { 0x00605B6A, 0x0000 },  // mov     eax, offset Unlockables -> 0x027DD018
    { 0x00605C09, 0x0000 },  // mov     eax, offset Unlockables -> 0x027DD018
    { 0x0062811B, 0x0000 },  // mov     ecx, offset Unlockables -> 0x027DD018
    { 0x006B1DCD, 0x0030 },  // mov     eax, (offset Unlockables.mpu.m_data+28h) -> 0x027DD048
    { 0x006BAC05, 0x00C4 },  // mov     eax, offset Unlockables.is_unlocked -> 0x027DD0DC
    { 0x006BC809, 0x0000 },  // add     eax, offset Unlockables -> 0x027DD018
    { 0x006BC840, 0x0000 },  // mov     eax, offset Unlockables -> 0x027DD018
    { 0x006BC87F, 0x0000 },  // mov     eax, offset Unlockables -> 0x027DD018
    { 0x006BC8CE, 0x00C8 },  // mov     edi, offset Unlockables.item_this_trumps -> 0x027DD0E0
    { 0x006BC8DD, 0x0000 },  // mov     ecx, offset Unlockables -> 0x027DD018
    { 0x006BC902, 0x00CC },  // mov     Unlockables.item_trumper[eax], ecx -> 0x027DD0E4
    { 0x006BC9D8, 0x0000 },  // mov     edx, offset Unlockables -> 0x027DD018
    { 0x006BC9F8, 0x0000 },  // add     eax, offset Unlockables -> 0x027DD018
    { 0x006BCC14, 0x00C4 },  // mov     eax, offset Unlockables.is_unlocked -> 0x027DD0DC
    { 0x006BCD3F, 0x0000 },  // mov     ecx, offset Unlockables -> 0x027DD018
    { 0x006BCDA1, 0x0000 },  // mov     eax, offset Unlockables -> 0x027DD018
    { 0x006BCE20, 0x0000 },  // mov     ecx, offset Unlockables -> 0x027DD018
    { 0x006BCE60, 0x0000 },  // mov     ecx, offset Unlockables -> 0x027DD018
    { 0x006BCEA0, 0x0000 },  // mov     ecx, offset Unlockables -> 0x027DD018
    { 0x006BCEE0, 0x0000 },  // mov     ecx, offset Unlockables -> 0x027DD018
    { 0x006BCF20, 0x0000 },  // mov     ecx, offset Unlockables -> 0x027DD018
    { 0x006BCF60, 0x0000 },  // mov     eax, offset Unlockables -> 0x027DD018
    { 0x006BCF90, 0x0000 },  // mov     ecx, offset Unlockables -> 0x027DD018
    { 0x006BCFC0, 0x0000 },  // mov     ecx, offset Unlockables -> 0x027DD018
    { 0x006BD09D, 0x0030 },  // mov     ecx, (offset Unlockables.mpu.m_data+28h) -> 0x027DD048
    { 0x006BD158, 0x00CC },  // mov     ebx, offset Unlockables.item_trumper -> 0x027DD0E4
    { 0x006BD28F, 0x00C4 },  // mov     edi, offset Unlockables.is_unlocked -> 0x027DD0DC
    { 0x006BD2E7, 0x0008 },  // mov     esi, offset Unlockables.mpu -> 0x027DD020
    { 0x007504AE, 0x0000 },  // mov     ecx, offset Unlockables -> 0x027DD018
    { 0x007622C5, 0x0000 },  // mov     ecx, offset Unlockables -> 0x027DD018
    { 0x00DA9B27, 0x0000 },  // mov     eax, offset Unlockables -> 0x027DD018
    };

    const size_t Unlockables_Array_xref_count = sizeof(Unlockables_Array_xrefs) / sizeof(Unlockables_Array_xrefs[0]);


    void patch_Unlockables_Array_references(void* new_base) {
        for (size_t i = 0; i < Unlockables_Array_xref_count; i++) {
            void* patch_addr = (void*)Unlockables_Array_xrefs[i].patch_location;
            void* new_value = (void*)((uintptr_t)new_base + Unlockables_Array_xrefs[i].offset);

            Memory::VP::Patch<void*>(patch_addr, new_value);
            printf("Patched 0x%p -> 0x%p (offset +0x%zX)\n",
                patch_addr, new_value, Unlockables_Array_xrefs[i].offset);
        }
    }

    constexpr uint32_t kVanillaWeaponStoreBucketLimit = 16;
    constexpr uint32_t kWeaponStoreCategoryCount = 8;
    constexpr uint32_t kWeaponStoreBucketHardMax = 1024;

    struct weapon_store_bucket_layout
    {
        uint32_t bucket_capacity;
        uint32_t bucket_shift;
        uint32_t bucket_stride_bytes;
        uint32_t bucket_block_bytes;
        uint32_t cache_counts_offset;
        uint32_t cache_buckets_offset;
        uint32_t owned_counts_offset;
        uint32_t owned_buckets_offset;
        uint32_t shop_counts_offset;
        uint32_t shop_buckets_offset;
        uint32_t total_size;
    };

    static uint8_t* g_weapon_store_bucket_storage = nullptr;

    addr_xref Weapon_store_cache_count_xrefs[] = {
        { 0x007B1C10, 0x00 },
        { 0x007B1C15, 0x04 },
        { 0x007B1C1A, 0x08 },
        { 0x007B1C1F, 0x0C },
        { 0x007B1C24, 0x10 },
        { 0x007B1C29, 0x14 },
        { 0x007B1C2E, 0x18 },
        { 0x007B1C33, 0x1C },
        { 0x007B1C57, 0x00 },
        { 0x007B1C6F, 0x00 },
        { 0x007B273D, 0x00 },
    };

    addr_xref Weapon_store_cache_bucket_xrefs[] = {
        { 0x007B1BF9, 0x00 },
        { 0x007B1C68, 0x00 },
        { 0x007B277F, 0x00 },
        { 0x007B32FB, 0x00 },
        { 0x007B34AA, 0x00 },
    };

    addr_xref Weapon_store_owned_count_xrefs[] = {
        { 0x007B1CE4, 0x00 },
        { 0x007B1CE9, 0x04 },
        { 0x007B1CEE, 0x08 },
        { 0x007B1CF3, 0x0C },
        { 0x007B1CF8, 0x10 },
        { 0x007B1CFD, 0x14 },
        { 0x007B1D02, 0x18 },
        { 0x007B1D07, 0x1C },
        { 0x007B1B7E, 0x00 },
        { 0x007B1D52, 0x00 },
        { 0x007B1D6A, 0x00 },
    };

    addr_xref Weapon_store_owned_bucket_xrefs[] = {
        { 0x007B1B92, 0x00 },
        { 0x007B1BCD, 0x00 },
        { 0x007B1CAD, 0x00 },
        { 0x007B1D63, 0x00 },
    };

    addr_xref Weapon_store_shop_count_xrefs[] = {
        { 0x007B1CBC, 0x00 },
        { 0x007B1CC1, 0x04 },
        { 0x007B1CC6, 0x08 },
        { 0x007B1CCB, 0x0C },
        { 0x007B1CD0, 0x10 },
        { 0x007B1CD5, 0x14 },
        { 0x007B1CDA, 0x18 },
        { 0x007B1CDF, 0x1C },
        { 0x007B1DF1, 0x00 },
        { 0x007B1E09, 0x00 },
        { 0x007B274A, 0x00 },
    };

    addr_xref Weapon_store_shop_bucket_xrefs[] = {
        { 0x007B1C9C, 0x00 },
        { 0x007B1E02, 0x00 },
        { 0x007B2773, 0x00 },
        { 0x007B3314, 0x00 },
        { 0x007B331B, 0x00 },
        { 0x007B349B, 0x00 },
    };

    uint32_t read_weapon_store_bucket_limit(CIniReader& ini)
    {
        const auto raw_value = static_cast<uint32_t>(ini.ReadInteger(
            "LIMITS",
            "WeaponStoreBucketLimit",
            kVanillaWeaponStoreBucketLimit));

        uint32_t limit = (std::max)(raw_value, kVanillaWeaponStoreBucketLimit);
        if (limit > kWeaponStoreBucketHardMax)
        {
            lprintf("WeaponStoreBucketLimit requested %u, clamping to %u\n",
                limit, kWeaponStoreBucketHardMax);
            limit = kWeaponStoreBucketHardMax;
        }

        if (!std::has_single_bit(limit))
        {
            const auto rounded = std::bit_ceil(limit);
            const auto clamped = (std::min)(rounded, kWeaponStoreBucketHardMax);
            lprintf("WeaponStoreBucketLimit %u is not a power of two, rounding to %u\n",
                limit, clamped);
            limit = clamped;
        }

        return limit;
    }

    weapon_store_bucket_layout create_weapon_store_bucket_layout(uint32_t bucket_capacity)
    {
        weapon_store_bucket_layout layout{};
        layout.bucket_capacity = bucket_capacity;
        layout.bucket_shift = std::countr_zero(bucket_capacity);
        layout.bucket_stride_bytes = bucket_capacity * sizeof(uint32_t);
        layout.bucket_block_bytes = kWeaponStoreCategoryCount * layout.bucket_stride_bytes;
        layout.cache_counts_offset = 0;
        layout.cache_buckets_offset = sizeof(uint32_t) * kWeaponStoreCategoryCount;
        layout.owned_counts_offset = layout.cache_buckets_offset + layout.bucket_block_bytes;
        layout.owned_buckets_offset = layout.owned_counts_offset + sizeof(uint32_t) * kWeaponStoreCategoryCount;
        layout.shop_counts_offset = layout.owned_buckets_offset + layout.bucket_block_bytes;
        layout.shop_buckets_offset = layout.shop_counts_offset + sizeof(uint32_t) * kWeaponStoreCategoryCount;
        layout.total_size = layout.shop_buckets_offset + layout.bucket_block_bytes;
        return layout;
    }

    void patch_addr_xref_list(const addr_xref* xrefs, size_t count, uint8_t* new_base)
    {
        for (size_t i = 0; i < count; i++)
        {
            void* patch_addr = (void*)xrefs[i].patch_location;
            void* new_value = (void*)((uintptr_t)new_base + xrefs[i].offset);
            Memory::VP::Patch<void*>(patch_addr, new_value);
        }
    }

    void patch_weapon_store_bucket_limit(uint32_t bucket_capacity)
    {
        if (bucket_capacity == kVanillaWeaponStoreBucketLimit)
            return;

        const auto layout = create_weapon_store_bucket_layout(bucket_capacity);
        g_weapon_store_bucket_storage = new uint8_t[layout.total_size] {};

        auto* cache_counts = g_weapon_store_bucket_storage + layout.cache_counts_offset;
        auto* cache_buckets = g_weapon_store_bucket_storage + layout.cache_buckets_offset;
        auto* owned_counts = g_weapon_store_bucket_storage + layout.owned_counts_offset;
        auto* owned_buckets = g_weapon_store_bucket_storage + layout.owned_buckets_offset;
        auto* shop_counts = g_weapon_store_bucket_storage + layout.shop_counts_offset;
        auto* shop_buckets = g_weapon_store_bucket_storage + layout.shop_buckets_offset;

        lprintf("Patching weapon store bucket limit to %u (stride=0x%X, block=0x%X)\n",
            bucket_capacity,
            layout.bucket_stride_bytes,
            layout.bucket_block_bytes);

        patch_addr_xref_list(
            Weapon_store_cache_count_xrefs,
            sizeof(Weapon_store_cache_count_xrefs) / sizeof(Weapon_store_cache_count_xrefs[0]),
            cache_counts);
        patch_addr_xref_list(
            Weapon_store_cache_bucket_xrefs,
            sizeof(Weapon_store_cache_bucket_xrefs) / sizeof(Weapon_store_cache_bucket_xrefs[0]),
            cache_buckets);
        patch_addr_xref_list(
            Weapon_store_owned_count_xrefs,
            sizeof(Weapon_store_owned_count_xrefs) / sizeof(Weapon_store_owned_count_xrefs[0]),
            owned_counts);
        patch_addr_xref_list(
            Weapon_store_owned_bucket_xrefs,
            sizeof(Weapon_store_owned_bucket_xrefs) / sizeof(Weapon_store_owned_bucket_xrefs[0]),
            owned_buckets);
        patch_addr_xref_list(
            Weapon_store_shop_count_xrefs,
            sizeof(Weapon_store_shop_count_xrefs) / sizeof(Weapon_store_shop_count_xrefs[0]),
            shop_counts);
        patch_addr_xref_list(
            Weapon_store_shop_bucket_xrefs,
            sizeof(Weapon_store_shop_bucket_xrefs) / sizeof(Weapon_store_shop_bucket_xrefs[0]),
            shop_buckets);

        Memory::VP::Patch<void*>(
            (void*)0x007B1AAF,
            (void*)((uintptr_t)owned_buckets + layout.bucket_stride_bytes));

        Patch<uint32_t>(0x007B1BF1 + 1, layout.bucket_block_bytes);
        Patch<uint32_t>(0x007B1C94 + 1, layout.bucket_block_bytes);
        Patch<uint32_t>(0x007B1CA5 + 1, layout.bucket_block_bytes);

        Patch<uint8_t>(0x007B1AAA + 2, static_cast<uint8_t>(layout.bucket_shift + 2));
        Patch<uint8_t>(0x007B1B8E + 2, static_cast<uint8_t>(layout.bucket_shift + 2));
        Patch<uint8_t>(0x007B2762 + 2, static_cast<uint8_t>(layout.bucket_shift + 2));

        Patch<uint8_t>(0x007B1C5D + 2, static_cast<uint8_t>(layout.bucket_shift));
        Patch<uint8_t>(0x007B1D58 + 2, static_cast<uint8_t>(layout.bucket_shift));
        Patch<uint8_t>(0x007B1DF7 + 2, static_cast<uint8_t>(layout.bucket_shift));
        Patch<uint8_t>(0x007B1BC5 + 2, static_cast<uint8_t>(layout.bucket_shift));
        Patch<uint8_t>(0x007B32EA + 2, static_cast<uint8_t>(layout.bucket_shift));
        Patch<uint8_t>(0x007B3488 + 2, static_cast<uint8_t>(layout.bucket_shift));
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



#pragma pack(push, 1)
    struct unlockable_item
    {
        checksum_stri checksum;
        char padding[0xC0];
        bool is_unlocked;
        bool dlc_start_unlocked;
        char unk[0xA];
    };
    struct unlockables_ext_header
    {
        uint32_t count;
    };

    struct unlockables_ext_entry
    {
        uint32_t checksum;
        uint8_t unlocked;
        uint8_t reserved[3];
    };

    struct crib_weapons_ext_header
    {
        uint32_t count;
        uint32_t weapon_info_count;
    };

    struct crib_weapons_ext_entry
    {
        uint32_t checksum;
        uint8_t unlocked;
        uint8_t reserved[3];
    };

    struct checksum_lookup_entry
    {
        uint32_t checksum;
        uint8_t enabled;
    };
#pragma pack(pop)

    uint32_t* Num_unlockable_items = (uint32_t*)0x0145A29C_g;
    constexpr const char* kUnlockablesExtChunkName = "unlockables_ext";
    constexpr uint32_t kUnlockablesExtChunkVersion = 1;
    constexpr const char* kCribWeaponsExtChunkName = "crib_weapons_ext";
    constexpr uint32_t kCribWeaponsExtChunkVersion = 1;
    constexpr uint32_t kCribWeaponUnlockedFlag = 0x08000000;
    constexpr uint32_t kRetailWeaponInfoStride = 0x498;
    constexpr uint32_t kRetailWeaponInfoNameOffset = 0x0;
    constexpr uint32_t kRetailWeaponInfoFlagsOffset = 0xC;
    const uintptr_t kRetailUnlockablesBase = 0x027DD018_g;
    unlockable_item* new_unlockables_array = nullptr;
    std::once_flag g_crib_weapons_ext_name_popup_once;
    bool g_pending_extended_misc_unlockables_load = false;
    bool g_active_extended_misc_unlockables_load = false;

    using unlockable_load_fn = void(__cdecl*)(bit_array* array);
    unlockable_load_fn g_unlockable_load = reinterpret_cast<unlockable_load_fn>(0x6BD2D0_g);
    using unlock_item_fn = void(__fastcall*)(unlockable_item* item, int unused);
    unlock_item_fn g_unlock_item = reinterpret_cast<unlock_item_fn>(0x6BBD50_g);
    using crib_weapon_load_abi = uc::abi<
        uc::eax_ret<int>,
        uc::edi_arg<bit_array*>>;
    crib_weapon_load_abi::callback_t g_crib_weapon_load_hook_callback;

    unlockable_item* get_unlockables_array()
    {
        if (new_unlockables_array)
            return new_unlockables_array;

        return reinterpret_cast<unlockable_item*>(kRetailUnlockablesBase);
    }

    uint32_t get_unlockables_count()
    {
        return Num_unlockable_items ? *Num_unlockable_items : 0;
    }

    int find_unlockable_index_by_checksum(uint32_t checksum)
    {
        auto unlockables = get_unlockables_array();
        auto count = get_unlockables_count();

        for (uint32_t i = 0; i < count; i++)
        {
            if (unlockables[i].checksum.checksum == checksum)
                return static_cast<int>(i);
        }

        return -1;
    }

    void unlockable_load(bit_array* array)
    {
        g_unlockable_load(array);
    }

    crib_weapon_load_abi::function_t& get_crib_weapon_load()
    {
        static auto load_fn = crib_weapon_load_abi::make(0xB74070_g);
        return load_fn;
    }

    uint8_t* get_weapon_infos_array()
    {
        auto base_ptr = reinterpret_cast<uint8_t**>(0x022D7BCC_g);
        return base_ptr ? *base_ptr : nullptr;
    }

    uint32_t get_weapon_infos_count()
    {
        auto count_ptr = reinterpret_cast<uint32_t*>(0x022D7BD0_g);
        return count_ptr ? *count_ptr : 0;
    }

    uint8_t* get_weapon_info_at(uint8_t* weapon_infos, uint32_t index)
    {
        if (!weapon_infos)
            return nullptr;

        return weapon_infos + (static_cast<size_t>(index) * kRetailWeaponInfoStride);
    }

    const char* get_weapon_info_name(const uint8_t* weapon)
    {
        return *reinterpret_cast<const char* const*>(weapon + kRetailWeaponInfoNameOffset);
    }

    uint32_t get_weapon_info_flags(const uint8_t* weapon)
    {
        return *reinterpret_cast<const uint32_t*>(weapon + kRetailWeaponInfoFlagsOffset);
    }

    bool is_crib_weapon_unlocked(const uint8_t* weapon)
    {
        return weapon && (get_weapon_info_flags(weapon) & kCribWeaponUnlockedFlag) != 0;
    }

    void show_crib_weapons_ext_name_error_popup(const char* phase, uint32_t index, uint32_t weapon_count)
    {
        std::call_once(g_crib_weapons_ext_name_popup_once, [phase, index, weapon_count]()
            {
                char buffer[512]{};
                snprintf(
                    buffer,
                    sizeof(buffer),
                    "CribWeaponsExt hit a weapon_info with a null or invalid name pointer while %s.\n\n"
                    "index=%u\n"
                    "Num_weapon_infos=%u\n\n"
                    "That entry will be skipped for the extended checksum save/load path.\n"
                    "Vanilla crib weapon save data is still kept as fallback.",
                    phase ? phase : "processing crib weapon checksums",
                    index,
                    weapon_count);

                MessageBoxA(
                    nullptr,
                    buffer,
                    "SR2 Limit Adjuster - CribWeaponsExt warning",
                    MB_OK | MB_ICONWARNING | MB_TOPMOST);
            });
    }

    bool try_get_weapon_name_checksum(
        const uint8_t* weapon,
        uint32_t index,
        uint32_t weapon_count,
        const char* phase,
        uint32_t& checksum_out)
    {
        if (!weapon)
        {
            show_crib_weapons_ext_name_error_popup(phase, index, weapon_count);
            lprintf("CribWeaponsExt: null weapon_info pointer while %s at index %u/%u\n",
                phase ? phase : "<unknown>",
                index,
                weapon_count);
            return false;
        }

        __try
        {
            const char* name = get_weapon_info_name(weapon);
            if (!name || !*name)
            {
                show_crib_weapons_ext_name_error_popup(phase, index, weapon_count);
                lprintf("CribWeaponsExt: null/empty weapon name while %s at index %u/%u\n",
                    phase ? phase : "<unknown>",
                    index,
                    weapon_count);
                return false;
            }

            checksum_out = static_cast<uint32_t>(str_to_hash(name));
            return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            show_crib_weapons_ext_name_error_popup(phase, index, weapon_count);
            lprintf("CribWeaponsExt: exception reading weapon name while %s at index %u/%u\n",
                phase ? phase : "<unknown>",
                index,
                weapon_count);
            return false;
        }
    }

    int weapons_load_crib_availability(bit_array* array)
    {
        return get_crib_weapon_load()(array);
    }

    bool should_override_misc_unlockables_now(uint32_t tag)
    {
        return g_active_extended_misc_unlockables_load && ExtendedSaves::HasChunk(tag);
    }

    bool is_unlockables_save_ext_enabled()
    {
        return AdjusterOptions.unlockables_save_ext_enabled != 0;
    }

    bool is_weapon_infos_save_ext_enabled()
    {
        return AdjusterOptions.weapon_infos_save_ext_enabled != 0;
    }

    template <typename Header, typename Entry>
    std::vector<uint8_t> build_ext_payload(const Header& header, const std::vector<Entry>& entries)
    {
        std::vector<uint8_t> payload(
            sizeof(Header) + (sizeof(Entry) * entries.size()),
            0);

        memcpy(payload.data(), &header, sizeof(Header));
        if (!entries.empty())
        {
            memcpy(
                payload.data() + sizeof(Header),
                entries.data(),
                sizeof(Entry) * entries.size());
        }

        return payload;
    }

    template <typename Header, typename Entry>
    const Entry* get_valid_ext_entries(
        const char* chunk_name,
        uint32_t expected_version,
        const char* save_name,
        const Header*& header_out,
        uint32_t& entry_count_out)
    {
        const auto chunk = ExtendedSaves::GetChunk(chunk_name);
        if (!chunk)
            return nullptr;

        if (chunk.version != expected_version || chunk.size < sizeof(Header))
        {
            lprintf("%s: ignoring invalid chunk for %s (version=%u size=%u)\n",
                chunk_name,
                save_name ? save_name : "<null>",
                chunk.version,
                chunk.size);
            return nullptr;
        }

        const auto* header = reinterpret_cast<const Header*>(chunk.data);
        const auto expected_size = sizeof(Header) + (sizeof(Entry) * header->count);
        if (chunk.size != expected_size)
        {
            lprintf("%s: ignoring malformed chunk for %s (count=%u size=%u expected=%u)\n",
                chunk_name,
                save_name ? save_name : "<null>",
                header->count,
                chunk.size,
                static_cast<uint32_t>(expected_size));
            return nullptr;
        }

        header_out = header;
        entry_count_out = header->count;
        return reinterpret_cast<const Entry*>(chunk.data + sizeof(Header));
    }

    template <typename FindIndexFn>
    uint32_t populate_bit_array_from_checksum_entries(
        bit_array& array,
        const checksum_lookup_entry* entries,
        uint32_t entry_count,
        FindIndexFn&& find_index,
        uint32_t& missing_count)
    {
        uint32_t applied_count = 0;
        missing_count = 0;

        for (uint32_t i = 0; i < entry_count; i++)
        {
            if (!entries[i].enabled)
                continue;

            const int index = find_index(entries[i].checksum);
            if (index < 0)
            {
                missing_count++;
                continue;
            }

            if (!array.set_bit(static_cast<uint32_t>(index)))
                continue;

            applied_count++;
        }

        return applied_count;
    }

    bool apply_unlockables_ext_from_chunk(const char* save_name)
    {
        const unlockables_ext_header* header = nullptr;
        uint32_t entry_count = 0;
        const auto* raw_entries = get_valid_ext_entries<unlockables_ext_header, unlockables_ext_entry>(
            kUnlockablesExtChunkName,
            kUnlockablesExtChunkVersion,
            save_name,
            header,
            entry_count);
        if (!raw_entries)
            return false;

        auto current_count = get_unlockables_count();
        std::vector<uint8_t> bit_storage((current_count + 7) / 8, 0);
        auto array = bit_array::from_storage(bit_storage.data(), static_cast<unsigned int>(bit_storage.size()));
        std::vector<checksum_lookup_entry> entries(entry_count);
        for (uint32_t i = 0; i < entry_count; i++)
        {
            entries[i].checksum = raw_entries[i].checksum;
            entries[i].enabled = raw_entries[i].unlocked;
        }

        uint32_t missing_count = 0;
        const auto applied_count = populate_bit_array_from_checksum_entries(
            array,
            entries.data(),
            entry_count,
            [](uint32_t checksum)
            {
                return find_unlockable_index_by_checksum(checksum);
            },
            missing_count);

        unlockable_load(&array);
        lprintf("UnlockablesExt: loaded %u unlockables for %s (%u missing checksums)\n",
            applied_count,
            save_name ? save_name : "<null>",
            missing_count);
        return true;
    }

    bool apply_crib_weapons_ext_from_chunk(const char* save_name)
    {
        const crib_weapons_ext_header* header = nullptr;
        uint32_t entry_count = 0;
        const auto* raw_entries = get_valid_ext_entries<crib_weapons_ext_header, crib_weapons_ext_entry>(
            kCribWeaponsExtChunkName,
            kCribWeaponsExtChunkVersion,
            save_name,
            header,
            entry_count);
        if (!raw_entries)
            return false;

        auto* weapon_infos = get_weapon_infos_array();
        const auto current_count = get_weapon_infos_count();
        if (!weapon_infos || current_count == 0)
        {
            lprintf("CribWeaponsExt: no weapon infos available while loading %s\n",
                save_name ? save_name : "<null>");
            return false;
        }

        struct checksum_candidates
        {
            std::vector<uint32_t> unlocked_indices;
            std::vector<uint32_t> locked_indices;
        };

        std::unordered_map<uint32_t, checksum_candidates> candidates;
        uint32_t skipped_current_count = 0;

        for (uint32_t i = 0; i < current_count; i++)
        {
            auto* weapon = get_weapon_info_at(weapon_infos, i);
            uint32_t checksum = 0;
            if (!try_get_weapon_name_checksum(weapon, i, current_count, "loading crib weapon checksums", checksum))
            {
                skipped_current_count++;
                continue;
            }

            auto& bucket = candidates[checksum];
            if (is_crib_weapon_unlocked(weapon))
                bucket.unlocked_indices.push_back(i);
            else
                bucket.locked_indices.push_back(i);
        }

        std::unordered_map<uint32_t, uint32_t> unlocked_positions;
        std::unordered_map<uint32_t, uint32_t> locked_positions;
        std::vector<uint8_t> bit_storage((current_count + 7) / 8, 0);
        auto array = bit_array::from_storage(bit_storage.data(), static_cast<unsigned int>(bit_storage.size()));
        uint32_t applied_count = 0;
        uint32_t missing_count = 0;

        for (uint32_t i = 0; i < entry_count; i++)
        {
            if (!raw_entries[i].unlocked)
                continue;

            const auto it = candidates.find(raw_entries[i].checksum);
            if (it == candidates.end())
            {
                missing_count++;
                continue;
            }

            auto& bucket = it->second;
            auto& unlocked_pos = unlocked_positions[raw_entries[i].checksum];
            auto& locked_pos = locked_positions[raw_entries[i].checksum];

            uint32_t chosen_index = UINT32_MAX;
            if (unlocked_pos < bucket.unlocked_indices.size())
                chosen_index = bucket.unlocked_indices[unlocked_pos++];
            else if (locked_pos < bucket.locked_indices.size())
                chosen_index = bucket.locked_indices[locked_pos++];
            else
            {
                missing_count++;
                continue;
            }

            if (!array.set_bit(chosen_index))
            {
                missing_count++;
                continue;
            }

            applied_count++;
        }

        weapons_load_crib_availability(&array);
        lprintf("CribWeaponsExt: loaded %u crib weapon entries for %s (%u missing checksums, %u current invalid names, save_count=%u current_count=%u)\n",
            applied_count,
            save_name ? save_name : "<null>",
            missing_count,
            skipped_current_count,
            header->weapon_info_count,
            current_count);
        return true;
    }

    void replay_dlc_unlock_side_effects()
    {
        auto unlockables = get_unlockables_array();
        auto count = get_unlockables_count();
        uint32_t replayed_count = 0;

        for (uint32_t i = 0; i < count; i++)
        {
            if (!unlockables[i].dlc_start_unlocked || !unlockables[i].is_unlocked)
                continue;

            g_unlock_item(&unlockables[i], 1);
            replayed_count++;
        }

        if (replayed_count)
            lprintf("UnlockablesExt: replayed %u DLC unlock side effects after checksum load.\n", replayed_count);
    }

    void __cdecl unlockable_load_hook(bit_array* array)
    {
        if (is_unlockables_save_ext_enabled()
            && should_override_misc_unlockables_now(ExtendedSaves::MakeTag(kUnlockablesExtChunkName)))
        {
            apply_unlockables_ext_from_chunk("<misc_unlockables>");
            return;
        }

        g_unlockable_load(array);
    }

    int __cdecl weapons_load_crib_availability_hook(bit_array* array)
    {
        if (is_weapon_infos_save_ext_enabled()
            && should_override_misc_unlockables_now(ExtendedSaves::MakeTag(kCribWeaponsExtChunkName)))
        {
            apply_crib_weapons_ext_from_chunk("<misc_unlockables>");
            return 1;
        }

        return weapons_load_crib_availability(array);
    }

     void* SAFETYHOOK_CCALL customize_item_system_init()
    {
         items_count = 0;

         if (AdjusterOptions.customization_items_limit.auto_mode)
         {
             auto items = xtbl_parse_table_node("customization_items.xtbl", (void*)0x0277307C_g);
             auto dlc_items = xtbl_parse_table_node("dlc_customization_items.xtbl", (void*)0x0277307C_g);
             items_count = xml_count(items, "Customization_Item");

             if (dlc_items)
             {
                 items_count += xml_count(dlc_items, "Customization_Item");
             }

             xtbl_free();
         }

         const auto items_capacity = resolve_capacity(
             "CustomizationItems",
             AdjusterOptions.customization_items_limit,
             items_count,
             kVanillaCustomizationItemsLimit);
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
           uint32_t object_info_count = 0;
           if (AdjusterOptions.items_3d_limit.auto_mode)
           {
               auto object_info = xtbl_parse_table_node("items_3d.xtbl", nullptr);
               object_info_count = xml_count(object_info, "Item");
               xtbl_free();
           }

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
              auto new_obj_items = new object_item_info[object_info_capacity]{};
               lprintf("Patching items_3d with %p count=%u capacity=%u\n", new_obj_items, object_info_count, object_info_capacity);
               patch_Obj_item_info_infos_references(new_obj_items);
           }

          uint32_t logos_count_wanted = 0;
          bool should_resolve_logos = !AdjusterOptions.customization_logos_limit.auto_mode;

          if (AdjusterOptions.customization_logos_limit.auto_mode)
          {
              auto root_logos = xtbl_parse_table_node("customization_logos.xtbl", nullptr);

              if (root_logos)
              {
                  logos_count_wanted = xml_count(root_logos, "Logo");
                  should_resolve_logos = true;
              }

              xtbl_free();
          }

           if (should_resolve_logos)
           {
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
                   auto new_logos_array = new customization_logo[logos_capacity]{};
                   lprintf("Patching customization_logos with %p count=%u capacity=%u\n", new_logos_array, logos_count_wanted, logos_capacity);
                   patch_Logos_Array_references(new_logos_array);
               }

          }

          uint32_t unlockables_count = 0;
          bool should_resolve_unlockables = !AdjusterOptions.unlockables_limit.auto_mode;

          if (AdjusterOptions.unlockables_limit.auto_mode)
          {
              auto unlockables_xml = xtbl_parse_table_node("unlockables.xtbl", nullptr);

              if (unlockables_xml)
              {
                  unlockables_count = xml_count(unlockables_xml, "Unlockable");

                  auto dlc_unlockables_xml = xtbl_parse_table_node("dlc_unlockables.xtbl", nullptr);

                  if (dlc_unlockables_xml)
                  {
                      unlockables_count += xml_count(dlc_unlockables_xml, "Unlockable");
                  }

                  should_resolve_unlockables = true;
              }

              xtbl_free();
          }

          if (should_resolve_unlockables)
          {
              const auto unlockables_capacity = resolve_capacity(
                  "Unlockables",
                  AdjusterOptions.unlockables_limit,
                 unlockables_count,
                 150);

             if (should_apply_capacity_patch(
                 AdjusterOptions.force_dyn,
                 AdjusterOptions.unlockables_limit,
                 unlockables_capacity,
                 150))
             {
                 new_unlockables_array = new unlockable_item[unlockables_capacity]{};
                 lprintf("Patching Unlockables with %p count=%u capacity=%u\n", new_unlockables_array, unlockables_count, unlockables_capacity);
                  patch_Unlockables_Array_references(new_unlockables_array);
                  Patch<size_t>(0x6BC990 + 1, unlockables_capacity);
              }
          }

          return sr2_init_stage_2D.unsafe_ccall<int>();
      }

     static void OnBeforeSaveUnlockables(const char* save_name)
     {
         if (!is_unlockables_save_ext_enabled())
         {
             ExtendedSaves::RemoveChunk(kUnlockablesExtChunkName);
             return;
         }

         auto unlockables = get_unlockables_array();
         auto count = get_unlockables_count();

         std::vector<unlockables_ext_entry> entries(count);
         for (uint32_t i = 0; i < count; i++)
         {
             entries[i].checksum = unlockables[i].checksum.checksum;
             entries[i].unlocked = unlockables[i].is_unlocked ? 1 : 0;
         }

         const unlockables_ext_header header{
             count
         };
         auto payload = build_ext_payload(header, entries);

         ExtendedSaves::SetChunk(
             kUnlockablesExtChunkName,
             payload.data(),
             static_cast<uint32_t>(payload.size()),
             kUnlockablesExtChunkVersion);

         lprintf("UnlockablesExt: saved %u unlockables for %s\n",
             count,
             save_name ? save_name : "<null>");
     }

     static void OnBeforeSaveCribWeapons(const char* save_name)
     {
         if (!is_weapon_infos_save_ext_enabled())
         {
             ExtendedSaves::RemoveChunk(kCribWeaponsExtChunkName);
             return;
         }

         auto* weapon_infos = get_weapon_infos_array();
         const auto weapon_count = get_weapon_infos_count();

          if (!weapon_infos && weapon_count != 0)
          {
              const crib_weapons_ext_header empty_header{};
              const auto payload = build_ext_payload<crib_weapons_ext_header, crib_weapons_ext_entry>(
                  empty_header,
                  {});
              ExtendedSaves::SetChunk(
                  kCribWeaponsExtChunkName,
                  payload.data(),
                  static_cast<uint32_t>(payload.size()),
                  kCribWeaponsExtChunkVersion);

             lprintf("CribWeaponsExt: weapon infos base was null while saving %s, writing empty checksum chunk as fallback.\n",
                 save_name ? save_name : "<null>");
             return;
         }

         std::vector<crib_weapons_ext_entry> entries;
         entries.reserve(weapon_count);

         uint32_t skipped_count = 0;
         uint32_t unlocked_count = 0;

         for (uint32_t i = 0; i < weapon_count; i++)
         {
             auto* weapon = get_weapon_info_at(weapon_infos, i);
             uint32_t checksum = 0;
             if (!try_get_weapon_name_checksum(weapon, i, weapon_count, "saving crib weapon checksums", checksum))
             {
                 skipped_count++;
                 continue;
             }

             crib_weapons_ext_entry entry{};
             entry.checksum = checksum;
             entry.unlocked = is_crib_weapon_unlocked(weapon) ? 1 : 0;
             if (entry.unlocked)
                 unlocked_count++;

             entries.push_back(entry);
         }

         const crib_weapons_ext_header header{
             static_cast<uint32_t>(entries.size()),
             weapon_count
         };
         auto payload = build_ext_payload(header, entries);

         ExtendedSaves::SetChunk(
             kCribWeaponsExtChunkName,
             payload.data(),
             static_cast<uint32_t>(payload.size()),
             kCribWeaponsExtChunkVersion);

         lprintf("CribWeaponsExt: saved %u/%u crib weapon entries for %s (%u unlocked, %u skipped invalid names)\n",
             static_cast<uint32_t>(entries.size()),
             weapon_count,
             save_name ? save_name : "<null>",
             unlocked_count,
             skipped_count);
     }

     static void OnAfterLoadUnlockables(const char* save_name, bool has_extension)
     {
         if (!has_extension || !is_unlockables_save_ext_enabled())
             return;

         if (ExtendedSaves::HasChunk(ExtendedSaves::MakeTag(kUnlockablesExtChunkName)))
         {
             g_pending_extended_misc_unlockables_load = true;
             lprintf("UnlockablesExt: queued checksum override for %s\n",
                 save_name ? save_name : "<null>");
         }
     }

     static void OnAfterLoadCribWeapons(const char* save_name, bool has_extension)
     {
         if (!has_extension || !is_weapon_infos_save_ext_enabled())
             return;

         if (ExtendedSaves::HasChunk(ExtendedSaves::MakeTag(kCribWeaponsExtChunkName)))
         {
             g_pending_extended_misc_unlockables_load = true;
             lprintf("CribWeaponsExt: queued checksum override for %s\n",
                 save_name ? save_name : "<null>");
         }
     }

     SafetyHookInline load_misc_unlockablesD;

     void __cdecl load_misc_unlockables_hook(int save_game_ptr, char load_activities_and_unlockables)
     {
         const bool should_override = g_pending_extended_misc_unlockables_load;
         g_pending_extended_misc_unlockables_load = false;
         g_active_extended_misc_unlockables_load = should_override;

         load_misc_unlockablesD.ccall<void>(save_game_ptr, load_activities_and_unlockables);

         g_active_extended_misc_unlockables_load = false;
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
        AdjusterOptions.unlockables_save_ext_enabled = ini.ReadInteger("SAVES", "UnlockablesExt", 1) != 0;
        AdjusterOptions.weapon_infos_save_ext_enabled = ini.ReadInteger("SAVES", "WeaponInfosExt", 1) != 0;
        AdjusterOptions.customization_items_limit = read_count_setting(
            ini, "LIMITS", "CustomizationItems", kVanillaCustomizationItemsLimit);
        AdjusterOptions.items_3d_limit = read_count_setting(
            ini, "LIMITS", "Items3D", kVanillaItems3DLimit);
        AdjusterOptions.customization_logos_limit = read_count_setting(
            ini, "LIMITS", "CustomizationLogos", kVanillaCustomizationLogosLimit);

        AdjusterOptions.unlockables_limit = read_count_setting(
            ini, "LIMITS", "Unlockables", 150);
        AdjusterOptions.weapon_store_bucket_limit = read_weapon_store_bucket_limit(ini);

        patch_weapon_store_bucket_limit(AdjusterOptions.weapon_store_bucket_limit);

        ExtendedSaves::InstallHooks();
        ExtendedSaves::RegisterBeforeSaveCallback(OnBeforeSaveUnlockables);
        ExtendedSaves::RegisterBeforeSaveCallback(OnBeforeSaveCribWeapons);
        ExtendedSaves::RegisterAfterLoadCallback(OnAfterLoadUnlockables);
        ExtendedSaves::RegisterAfterLoadCallback(OnAfterLoadCribWeapons);
        InterceptCall(0x694DD9_g, g_unlockable_load, unlockable_load_hook);
        g_crib_weapon_load_hook_callback = crib_weapon_load_abi::make_callback(weapons_load_crib_availability_hook);
        uc::patch_call(0x694DFC_g, g_crib_weapon_load_hook_callback.raw());
        load_misc_unlockablesD = safetyhook::create_inline(0x694BF0_g, load_misc_unlockables_hook);
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

