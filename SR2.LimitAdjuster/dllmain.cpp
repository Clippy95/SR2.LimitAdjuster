// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include <safetyhook.hpp>
#include "sr_xml.h"


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


namespace CLimitAdjuster
{

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
     void* SAFETYHOOK_CCALL customize_item_system_init()
    {
         auto items = xtbl_parse_table_node("customization_items.xtbl", (void*)0x0277307C_g);
         items_count = xml_count(items, "Customization_Item");
         xtbl_free();

         Patch<uint32_t>(0x7BF7D1 + 1, get_bytes(items_count, 32));
         Patch<uint32_t>(0x7BF7D1 + 1, get_bytes(items_count, 32));
         Patch<uint32_t>(0x7BF83E + 6, items_count);
         Patch<uint32_t>(0x7BF832 + 1, items_count * 4);
         Patch<uint32_t>(0x7BBAC6 + 1, items_count);
         Patch<uint32_t>(0x7BCC14 + 6, items_count);
         auto new_items = new customization_item[items_count];
         patch_customization_item_items_references(new_items);

        return customize_item_system_initD.unsafe_ccall<void*>();
    }
     SafetyHookInline sr2_init_stage_1D;
     char _cdecl sr2_init_stage_1_hook()
     {

         Patch<uint32_t>(0x51EE12 + 1, 737280 * 2);
         Patch<uint32_t>(0x51EE50 + 1, 737280 * 2);
         return sr2_init_stage_1D.unsafe_ccall<char>();
     }
    void Init()
    {
        static auto testing = safetyhook::create_mid(0x7BBA68_g, [](SafetyHookContext& ctx) {
            xml_element* node = (xml_element*)ctx.eax;
            });
        customize_item_system_initD = safetyhook::create_inline(0x7BF790_g, customize_item_system_init);
        sr2_init_stage_1D = safetyhook::create_inline(0x51D800, sr2_init_stage_1_hook);
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
        break;
    }
    return TRUE;
}

