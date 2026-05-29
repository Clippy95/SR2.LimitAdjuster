#pragma once

#include <cstddef>
#include <cstdint>

namespace CLimitAdjuster
{
	struct mempool_base;
	struct static_mempool_base;
	struct mempool;

	struct /*VFT*/ mempool_base_vtbl
	{
		void(__fastcall* set_thread_ownership)(mempool_base* thisa);
		bool(__fastcall* is_enabled)(mempool_base* thisa);
		bool(__fastcall* is_dynamic)(mempool_base* thisa);
		unsigned int(__fastcall* get_free_space_left)(mempool_base* thisa);
		unsigned int(__fastcall* get_used_space)(mempool_base* thisa);
		unsigned int(__fastcall* get_max_space)(mempool_base* thisa);
		bool(__fastcall* can_alloc)(mempool_base* thisa, void*, unsigned int, unsigned int);
		void* (__fastcall* alloc)(mempool_base* thisa, void*, unsigned int, unsigned int);
		void* (__fastcall* realloc)(mempool_base* thisa, void*, void*, unsigned int);
		bool(__fastcall* contains_address)(mempool_base* thisa, void*, void*);
		bool(__fastcall* clear)(mempool_base* thisa);
		void* (__fastcall* get_base)(mempool_base* thisa);
		unsigned int(__fastcall* mark)(mempool_base* thisa);
		bool(__fastcall* restore_to_mark)(mempool_base* thisa, void*, unsigned int);
		bool(__fastcall* release_bytes)(mempool_base* thisa, void*, unsigned int);
		bool(__fastcall* pad_to_page)(mempool_base* thisa, void*, unsigned int);
		void(__fastcall* mempool_base_deconstruct)(mempool_base* thisa);
	};

	struct mempool_base
	{
		mempool_base_vtbl* vft;
		uint8_t is_disabled;
		uint8_t pad_05[7];
		char name[32];
		int flags;
		void* unknown_30;
	};

	struct static_mempool_base : mempool_base
	{
		void* last_allocation;
		void* start_of_pool;
		int max_pool_size;
		int default_alignment;
		int pool_used;
		int pool_used_mark;
	};

	struct mempool : static_mempool_base
	{
		int end_pool_used;
		int end_pool_used_mark;
	};

	struct DynamicMempoolConfig
	{
		uint32_t reserve_size = 0;
		uint32_t grow_granularity = 0x10000;
	};

	bool RegisterGrowableMempool(static_mempool_base* pool, const DynamicMempoolConfig& config);
	void Mempool_init();
}
