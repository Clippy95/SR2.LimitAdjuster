#pragma once
#include <cstdint>
#include <string.h>
#include <stdlib.h>
#include "Math.h"
#include "framework.h"
#include "usercaller.hpp"
struct xml_element
{
	const char* name;
	xml_element* next;
	xml_element* elements;
	char* text;
};
typedef uint32_t(__thiscall* crc_strT)(const char* text);
inline crc_strT str_to_hash = (crc_strT)0x00BDC9B0_g;

inline auto xtbl_parse_table_node = uc::make<
	uc::eax_ret<xml_element*>,
	uc::eax_arg<const char*>,
	uc::ecx_arg<void*>
>(0xB743F0_g);


inline uint32_t checksum(xml_element* root, uint32_t accumulator)
{
	unsigned int result = accumulator;
	if (root)
	{
		if (root->name)
			result = str_to_hash(root->name) ^ result;

		if (root->text)
			result = str_to_hash(root->text) ^ result;

		for (xml_element* child = root->elements; child; child = child->next)
		{
			result = checksum(child, result);
		}
	}
	return result;
}
inline __declspec(naked) xml_element* parse_table_node(const char* filename, int* override_xtbl_mempool) {
	__asm {
		push ebp
		mov ebp, esp
		sub esp, __LOCAL_SIZE

		mov eax, filename
		mov ecx, override_xtbl_mempool
		mov edx, 0x00B743F0
		call edx

		mov esp, ebp
		pop ebp
		ret
	}
}

inline __declspec(naked) bool xtbl_get_bool(const char* item_name, bool* value_out, xml_element* branching) {
	__asm {
		push ebp
		mov ebp, esp
		sub esp, __LOCAL_SIZE

		mov ecx, item_name
		push branching
		push value_out
		mov edx, 0xB750D0
		call edx

		mov esp, ebp
		pop ebp
		ret
	}
}

inline xml_element* xtbl_find(const xml_element* element, const char* tag)
{
	xml_element* elements;

	if (!element)
		return 0;
	elements = element->elements;
	if (!elements)
		return 0;
	while (_stricmp(elements->name, tag))
	{
		elements = elements->next;
		if (!elements)
			return 0;
	}
	return elements;
}

inline xml_element* xtbl_find_next(xml_element* element, xml_element* current, const char* tag)
{
	if (!element || !current)
		return 0;
	while (true)
	{
		current = current->next;
		if (current)
		{
			if (!_strcmpi(current->name, tag))
				break;
		}
		if (!current)
			return 0;
	}
	return current;
}

inline const char* xtbl_get_req_string_ref(xml_element* root, const char* attribute_name)
{
	xml_element* node;

	if (!root)
		return 0;
	if (!attribute_name)
		return root->text;
	node = xtbl_find(root, attribute_name);
	if (node)
		return node->text;
	else
		return 0;
}

// adding some validations this might be good but it's good enough for now
inline float xtbl_get_float_lazy(xml_element* root, const char* attribute_name) {
	return(float)atof(xtbl_get_req_string_ref(root, attribute_name));
}

inline void xtbl_get_vector(vector3* vec, xml_element* root, const char* attribute_name)
{
	xml_element* vector_node = xtbl_find(root, attribute_name);
	vec->x = vec->y = vec->z = 0.0f;
	if (vector_node) {
		vec->x = xtbl_get_float_lazy(vector_node, "X");
		vec->y = xtbl_get_float_lazy(vector_node, "Y");
		vec->z = xtbl_get_float_lazy(vector_node, "Z");
	}

}

inline unsigned int __cdecl xml_count(xml_element* element, const char* tag)
{
	unsigned int count;
	xml_element* elementa = nullptr;

	count = 0;
	if (element)
	{
		for (elementa = element->elements; elementa; elementa = elementa->next)
		{
			if (!_strcmpi(elementa->name, tag))
				++count;
		}
	}
	return count;
}

inline xml_element* xml_find_child(xml_element* parent, const char* name)
{
	for (auto e = parent ? parent->elements : nullptr; e; e = e->next)
		if (!_stricmp(e->name, name))
			return e;
	return nullptr;
}

inline int xml_count_children(xml_element* parent, const char* name)
{
	int count = 0;
	for (auto e = parent ? parent->elements : nullptr; e; e = e->next)
		if (!_stricmp(e->name, name))
			++count;
	return count;
}
