#include "pch.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>

#include <safetyhook.hpp>

#include "include/MemoryMgr.h"
#include "Mempool.h"
#include <IniReader.h>
#include <usercaller.hpp>
#include <safetyhook_inline.hpp>

void lprintf(const char* format, ...);

#ifndef SR2_LIMIT_ADJUSTER_MEMPOOL_DEBUG_LOGS
#define SR2_LIMIT_ADJUSTER_MEMPOOL_DEBUG_LOGS 0
#endif

#if SR2_LIMIT_ADJUSTER_MEMPOOL_DEBUG_LOGS
#define MEMPOOL_LOG(...) lprintf(__VA_ARGS__)
#else
#define MEMPOOL_LOG(...) ((void)0)
#endif

namespace CLimitAdjuster
{
	namespace
	{
		constexpr uintptr_t kRetailStaticMempoolVtbl = 0x00E59480;
		constexpr uintptr_t kRetailMempoolVtbl = 0x00E58CD4;
		constexpr uint32_t kAutoReserveFloor = 0x04000000;
		constexpr uint32_t kAutoReserveMultiplier = 8;

		struct dynamic_pool_state
		{
			uint8_t* reserved_base = nullptr;
			uint32_t reserve_size = 0;
			uint32_t committed_size = 0;
			uint32_t grow_granularity = 0;
			bool managed_override = false;
		};

		struct inline_hook_slot
		{
			uintptr_t target = 0;
			SafetyHookInline hook{};
		};

		std::recursive_mutex g_dynamic_pool_mutex;
		std::unordered_map<static_mempool_base*, dynamic_pool_state> g_dynamic_pools;
		std::mutex g_string_pool_fallback_mutex;
		std::unordered_map<std::string, std::unique_ptr<char[]>> g_string_pool_fallbacks;
		std::once_flag g_effects_cpu_alloc_failure_popup_once;
		std::array<inline_hook_slot, 2> g_can_alloc_hooks{};
		std::array<inline_hook_slot, 2> g_alloc_hooks{};
		std::array<inline_hook_slot, 2> g_realloc_hooks{};
		std::array<inline_hook_slot, 2> g_contains_address_hooks{};
		std::array<inline_hook_slot, 2> g_clear_hooks{};
		std::array<inline_hook_slot, 2> g_get_base_hooks{};
		std::array<inline_hook_slot, 2> g_mark_hooks{};
		std::array<inline_hook_slot, 2> g_restore_to_mark_hooks{};
		std::array<inline_hook_slot, 2> g_release_bytes_hooks{};
		std::array<inline_hook_slot, 2> g_pad_to_page_hooks{};
		uintptr_t g_static_can_alloc_target = 0;
		uintptr_t g_static_alloc_target = 0;
		uintptr_t g_static_realloc_target = 0;
		uintptr_t g_static_contains_address_target = 0;
		uintptr_t g_static_clear_target = 0;
		uintptr_t g_static_get_base_target = 0;
		uintptr_t g_static_mark_target = 0;
		uintptr_t g_static_restore_to_mark_target = 0;
		uintptr_t g_static_release_bytes_target = 0;
		uintptr_t g_static_pad_to_page_target = 0;
		uint32_t g_page_size = 0x1000;
		bool g_mempool_hooks_installed = false;

		std::string make_ascii_lowercase_key(const char* string)
		{
			if (!string)
				return {};

			std::string key(string);
			for (char& ch : key)
			{
				if (ch >= 'A' && ch <= 'Z')
					ch = static_cast<char>(ch - 'A' + 'a');
			}
			return key;
		}

		const char* get_or_create_string_pool_fallback(const char* string)
		{
			if (!string || !string[0])
				return string;

			const auto key = make_ascii_lowercase_key(string);
			std::scoped_lock lock(g_string_pool_fallback_mutex);

			if (const auto it = g_string_pool_fallbacks.find(key); it != g_string_pool_fallbacks.end())
				return it->second.get();

			const auto length = std::strlen(string);
			auto copy = std::make_unique<char[]>(length + 1);
			std::memcpy(copy.get(), string, length + 1);
			const char* result = copy.get();
			g_string_pool_fallbacks.emplace(key, std::move(copy));
			return result;
		}

		uint32_t align_up(uint32_t value, uint32_t alignment)
		{
			if (alignment <= 1)
				return value;

			return (value + alignment - 1) & ~(alignment - 1);
		}

		uint32_t get_effective_alignment(const static_mempool_base* pool, unsigned int requested_alignment)
		{
			uint32_t alignment = requested_alignment ? requested_alignment : static_cast<uint32_t>(pool->default_alignment);
			if (alignment == 0)
				alignment = 4;

			return (std::max)(alignment, 4u);
		}

		std::string get_pool_name(const mempool_base* pool)
		{
			if (!pool)
				return {};

			size_t length = 0;
			while (length < sizeof(pool->name))
			{
				const unsigned char ch = static_cast<unsigned char>(pool->name[length]);
				if (ch == '\0')
					break;
				if (ch < 0x20 || ch > 0x7E)
					return {};
				++length;
			}

			if (length == 0 || length >= sizeof(pool->name))
				return {};

			return std::string(pool->name, pool->name + length);
		}

		bool looks_like_supported_pool(const static_mempool_base* pool)
		{
			if (!pool)
				return false;

			if (!pool->start_of_pool)
				return false;

			const auto max_pool_size = static_cast<uint32_t>(pool->max_pool_size);
			if (max_pool_size == 0 || max_pool_size > 0x40000000u)
				return false;

			if (pool->pool_used < 0 || static_cast<uint32_t>(pool->pool_used) > max_pool_size)
				return false;

			return !get_pool_name(pool).empty();
		}

		bool is_readable_range(const void* base, size_t size)
		{
			if (!base || size == 0)
				return false;

			const auto begin = reinterpret_cast<uintptr_t>(base);
			const auto end = begin + size;
			if (end < begin)
				return false;

			uintptr_t cursor = begin;
			while (cursor < end)
			{
				MEMORY_BASIC_INFORMATION mbi{};
				if (!VirtualQuery(reinterpret_cast<const void*>(cursor), &mbi, sizeof(mbi)))
					return false;

				if (mbi.State != MEM_COMMIT)
					return false;

				if ((mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) != 0)
					return false;

				const auto region_base = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
				const auto region_end = region_base + mbi.RegionSize;
				if (region_end <= cursor)
					return false;

				cursor = region_end;
			}

			return true;
		}

		template <typename Fn>
		Fn read_vtable_entry(uintptr_t vtable_address, size_t index)
		{
			return reinterpret_cast<Fn>(*reinterpret_cast<uintptr_t*>(vtable_address + index * sizeof(uintptr_t)));
		}

		template <typename Callback>
		void install_deduped_inline_hook(std::array<inline_hook_slot, 2>& hooks, uintptr_t target, Callback callback, const char* label)
		{
			if (!target)
				return;

			for (const auto& slot : hooks)
			{
				if (slot.target == target)
					return;
			}

			for (auto& slot : hooks)
			{
				if (slot.target != 0)
					continue;

				slot.hook = safetyhook::create_inline(reinterpret_cast<void*>(target), callback);
				if (!slot.hook)
				{
					MEMPOOL_LOG("Failed to install %s inline hook at %p\n", label, reinterpret_cast<void*>(target));
					return;
				}

				slot.target = target;
				MEMPOOL_LOG("Installed %s inline hook at %p\n", label, reinterpret_cast<void*>(target));
				return;
			}

			MEMPOOL_LOG("No free slot left for %s inline hook at %p\n", label, reinterpret_cast<void*>(target));
		}

		template <typename Ret, typename... Args>
		Ret call_inline_original_thiscall(std::array<inline_hook_slot, 2>& hooks, uintptr_t target, Args... args)
		{
			for (auto& slot : hooks)
			{
				if (slot.target == target && slot.hook)
					return slot.hook.unsafe_thiscall<Ret>(args...);
			}

			return Ret{};
		}

		bool needs_growth(const static_mempool_base* pool, unsigned int allocation_size, unsigned int alignment)
		{
			const uint32_t alloc_alignment = get_effective_alignment(pool, alignment);
			const uint32_t used = static_cast<uint32_t>(pool->pool_used);
			const uint32_t misalignment = (reinterpret_cast<uintptr_t>(pool->start_of_pool) + used) % alloc_alignment;
			const uint32_t adjust_for_alignment = misalignment ? (alloc_alignment - misalignment) : 0;
			const uint64_t required_total = static_cast<uint64_t>(used) + adjust_for_alignment + allocation_size;
			return required_total > static_cast<uint32_t>(pool->max_pool_size);
		}

		void* relocate_pool_pointer(const static_mempool_base* pool, const void* old_base, void* new_base, void* ptr)
		{
			if (!pool || !old_base || !new_base || !ptr)
				return ptr;

			const auto old_begin = reinterpret_cast<uintptr_t>(old_base);
			const auto old_end = old_begin + static_cast<uint32_t>(pool->max_pool_size);
			const auto value = reinterpret_cast<uintptr_t>(ptr);
			if (value < old_begin || value >= old_end)
				return ptr;

			const auto offset = value - old_begin;
			return static_cast<uint8_t*>(new_base) + offset;
		}

		bool register_pool_locked(static_mempool_base* pool, const DynamicMempoolConfig* explicit_config)
		{
			const auto pool_name = get_pool_name(pool);
			MEMPOOL_LOG("register_pool_locked pool=%p name=%s used=0x%X mark=0x%X max=0x%X start=%p\n",
				pool,
				pool_name.empty() ? "<invalid>" : pool_name.c_str(),
				pool ? pool->pool_used : 0,
				pool ? pool->pool_used_mark : 0,
				pool ? pool->max_pool_size : 0,
				pool ? pool->start_of_pool : nullptr);

			if (g_dynamic_pools.contains(pool))
				return true;

			const uint32_t initial_size = align_up(static_cast<uint32_t>(pool->max_pool_size), g_page_size);
			const uint64_t auto_reserve = (std::max<uint64_t>)(
				static_cast<uint64_t>(initial_size) * kAutoReserveMultiplier,
				kAutoReserveFloor);
			const uint32_t reserve_from_config = explicit_config ? explicit_config->reserve_size : 0;
			const uint32_t reserve_size = align_up(
				static_cast<uint32_t>((std::max<uint64_t>)(
					static_cast<uint64_t>(initial_size),
					static_cast<uint64_t>(reserve_from_config ? reserve_from_config : static_cast<uint32_t>((std::min<uint64_t>)(auto_reserve, 0xFFFFFFFFull))))),
				g_page_size);
			const uint32_t configured_granularity = explicit_config ? explicit_config->grow_granularity : 0;
			const uint32_t grow_granularity = (std::max)(
				align_up(configured_granularity ? configured_granularity : initial_size, g_page_size),
				0x10000u);

			auto* reserved_base = static_cast<uint8_t*>(VirtualAlloc(nullptr, reserve_size, MEM_RESERVE, PAGE_READWRITE));
			if (!reserved_base)
			{
				MEMPOOL_LOG("Mempool %s at %p failed reserve of 0x%X bytes (error=%lu)\n",
					pool_name.empty() ? "<invalid>" : pool_name.c_str(),
					pool,
					reserve_size,
					GetLastError());
				return false;
			}

			if (!VirtualAlloc(reserved_base, initial_size, MEM_COMMIT, PAGE_READWRITE))
			{
				const auto error = GetLastError();
				VirtualFree(reserved_base, 0, MEM_RELEASE);
				MEMPOOL_LOG("Mempool %s at %p failed commit of 0x%X bytes (error=%lu)\n",
					pool_name.empty() ? "<invalid>" : pool_name.c_str(),
					pool,
					initial_size,
					error);
				return false;
			}

			auto* old_start = pool->start_of_pool;
			auto* old_last_allocation = pool->last_allocation;
			const uint32_t copy_size = (std::clamp)(static_cast<uint32_t>((std::max)(pool->pool_used, 0)), 0u, static_cast<uint32_t>(pool->max_pool_size));
			if (copy_size != 0)
			{
				if (!is_readable_range(old_start, copy_size))
				{
					MEMPOOL_LOG("Mempool %s at %p has unreadable live backing: old_start=%p copy_size=0x%X max=0x%X used=0x%X\n",
						pool_name.empty() ? "<invalid>" : pool_name.c_str(),
						pool,
						old_start,
						copy_size,
						pool->max_pool_size,
						pool->pool_used);
					VirtualFree(reserved_base, 0, MEM_RELEASE);
					return false;
				}

				std::memcpy(reserved_base, old_start, copy_size);
			}

			pool->start_of_pool = reserved_base;
			pool->last_allocation = relocate_pool_pointer(pool, old_start, reserved_base, old_last_allocation);
			pool->max_pool_size = static_cast<int>(initial_size);

			g_dynamic_pools.emplace(pool, dynamic_pool_state{
				.reserved_base = reserved_base,
				.reserve_size = reserve_size,
				.committed_size = initial_size,
				.grow_granularity = grow_granularity,
			});

			MEMPOOL_LOG("Registered growable mempool %s at %p: commit=0x%X reserve=0x%X granularity=0x%X\n",
				pool_name.empty() ? "<invalid>" : pool_name.c_str(),
				pool,
				initial_size,
				reserve_size,
				grow_granularity);
			if (old_start && old_start != reserved_base)
			{
				MEMPOOL_LOG("Mempool %s at %p migrated live pool backing: old_start=%p new_start=%p old_last=%p new_last=%p used=0x%X mark=0x%X\n",
					pool_name.empty() ? "<invalid>" : pool_name.c_str(),
					pool,
					old_start,
					reserved_base,
					old_last_allocation,
					pool->last_allocation,
					pool->pool_used,
					pool->pool_used_mark);
			}
			return true;
		}

		bool grow_pool_locked(static_mempool_base* pool, unsigned int allocation_size, unsigned int alignment, const char* reason)
		{
			const auto pool_name = get_pool_name(pool);
			MEMPOOL_LOG("grow_pool_locked pool=%p name=%s reason=%s size=0x%X alignment=0x%X used=0x%X max=0x%X start=%p\n",
				pool,
				pool_name.empty() ? "<invalid>" : pool_name.c_str(),
				reason ? reason : "<null>",
				allocation_size,
				alignment,
				pool ? pool->pool_used : 0,
				pool ? pool->max_pool_size : 0,
				pool ? pool->start_of_pool : nullptr);

			const auto it = g_dynamic_pools.find(pool);
			if (it == g_dynamic_pools.end())
				return false;

			auto& state = it->second;
			const uint32_t alloc_alignment = get_effective_alignment(pool, alignment);
			const uint32_t used = static_cast<uint32_t>(pool->pool_used);
			const uint32_t misalignment = (reinterpret_cast<uintptr_t>(pool->start_of_pool) + used) % alloc_alignment;
			const uint32_t adjust_for_alignment = misalignment ? (alloc_alignment - misalignment) : 0;
			const uint64_t required_total = static_cast<uint64_t>(used) + adjust_for_alignment + allocation_size;

			if (required_total <= state.committed_size)
			{
				MEMPOOL_LOG("Mempool %s at %p already has room for %s: required=0x%llX committed=0x%X reserve=0x%X\n",
					pool_name.empty() ? "<invalid>" : pool_name.c_str(),
					pool,
					reason,
					required_total,
					state.committed_size,
					state.reserve_size);
				return true;
			}

			if (required_total > state.reserve_size)
			{
				MEMPOOL_LOG("Mempool %s at %p cannot grow for %s: need 0x%llX bytes, reserve cap is 0x%X\n",
					pool_name.empty() ? "<invalid>" : pool_name.c_str(),
					pool,
					reason,
					required_total,
					state.reserve_size);
				return false;
			}

			const uint32_t requested_size = static_cast<uint32_t>(required_total);
			const uint32_t growth_target = (std::max)(requested_size, state.committed_size + state.grow_granularity);
			const uint32_t new_committed_size = align_up(growth_target, g_page_size);
			if (new_committed_size > state.reserve_size)
			{
				MEMPOOL_LOG("Mempool %s at %p cannot grow for %s: rounded target 0x%X exceeds reserve cap 0x%X\n",
					pool_name.empty() ? "<invalid>" : pool_name.c_str(),
					pool,
					reason,
					new_committed_size,
					state.reserve_size);
				return false;
			}

			auto* commit_base = state.reserved_base + state.committed_size;
			const uint32_t commit_size = new_committed_size - state.committed_size;
			MEMPOOL_LOG("Mempool %s at %p committing for %s: commit_base=%p commit_size=0x%X old_commit=0x%X new_commit=0x%X\n",
				pool_name.empty() ? "<invalid>" : pool_name.c_str(),
				pool,
				reason,
				commit_base,
				commit_size,
				state.committed_size,
				new_committed_size);
			if (!VirtualAlloc(commit_base, commit_size, MEM_COMMIT, PAGE_READWRITE))
			{
				MEMPOOL_LOG("Mempool %s at %p failed to commit 0x%X bytes for %s (error=%lu)\n",
					pool_name.empty() ? "<invalid>" : pool_name.c_str(),
					pool,
					commit_size,
					reason,
					GetLastError());
				return false;
			}

			state.committed_size = new_committed_size;
			pool->max_pool_size = static_cast<int>(new_committed_size);
			MEMPOOL_LOG("Mempool %s at %p grew for %s: commit 0x%X -> 0x%X (reserve 0x%X)\n",
				pool_name.empty() ? "<invalid>" : pool_name.c_str(),
				pool,
				reason,
				new_committed_size - commit_size,
				new_committed_size,
				state.reserve_size);
			return true;
		}

		bool is_pool_managed_locked(const static_mempool_base* pool)
		{
			if (const auto it = g_dynamic_pools.find(const_cast<static_mempool_base*>(pool)); it != g_dynamic_pools.end())
				return it->second.managed_override;
			return false;
		}

		void enable_managed_override_locked(static_mempool_base* pool, const char* reason)
		{
			if (const auto it = g_dynamic_pools.find(pool); it != g_dynamic_pools.end())
			{
				if (!it->second.managed_override)
				{
					it->second.managed_override = true;
					MEMPOOL_LOG("Mempool %s at %p switched to managed override (%s)\n",
						get_pool_name(pool).c_str(),
						pool,
						reason ? reason : "<null>");
				}
			}
		}

		bool managed_can_alloc_locked(const static_mempool_base* pool, unsigned int allocation_size, unsigned int alignment)
		{
			const uint32_t alloc_alignment = get_effective_alignment(pool, alignment);
			const uint32_t used = static_cast<uint32_t>(pool->pool_used);
			const uint32_t misalignment = (reinterpret_cast<uintptr_t>(pool->start_of_pool) + used) % alloc_alignment;
			const uint32_t adjust_for_alignment = misalignment ? (alloc_alignment - misalignment) : 0;
			const uint64_t required_total = static_cast<uint64_t>(used) + adjust_for_alignment + allocation_size;
			return required_total <= static_cast<uint32_t>(pool->max_pool_size);
		}

		void* managed_alloc_locked(static_mempool_base* pool, unsigned int allocation_size, unsigned int alignment)
		{
			if (!managed_can_alloc_locked(pool, allocation_size, alignment))
				return nullptr;

			const uint32_t alloc_alignment = get_effective_alignment(pool, alignment);
			const uint32_t used = static_cast<uint32_t>(pool->pool_used);
			const uint32_t misalignment = (reinterpret_cast<uintptr_t>(pool->start_of_pool) + used) % alloc_alignment;
			const uint32_t adjust_for_alignment = misalignment ? (alloc_alignment - misalignment) : 0;
			auto* result = static_cast<uint8_t*>(pool->start_of_pool) + used + adjust_for_alignment;
			pool->last_allocation = result;
			pool->pool_used = static_cast<int>(used + adjust_for_alignment + allocation_size);
			return result;
		}

		void* managed_realloc_locked(static_mempool_base* pool, void* addr_start, unsigned int new_size)
		{
			if (!addr_start || addr_start != pool->last_allocation)
				return nullptr;

			const auto base = reinterpret_cast<uintptr_t>(pool->start_of_pool);
			const auto current = reinterpret_cast<uintptr_t>(addr_start);
			if (current < base)
				return nullptr;

			const uint64_t new_used = static_cast<uint64_t>(current - base) + new_size;
			if (new_used > static_cast<uint32_t>(pool->max_pool_size))
				return nullptr;

			pool->pool_used = static_cast<int>(new_used);
			return addr_start;
		}

		bool managed_pad_to_page_locked(static_mempool_base* pool, unsigned int alignment)
		{
			const uint32_t page_alignment = alignment ? alignment : g_page_size;
			const uint32_t used = static_cast<uint32_t>(pool->pool_used);
			const uint32_t misalignment = (reinterpret_cast<uintptr_t>(pool->start_of_pool) + used) % page_alignment;
			if (misalignment == 0)
				return true;

			const uint32_t padding = page_alignment - misalignment;
			return managed_alloc_locked(pool, padding, 1) != nullptr;
		}

		bool managed_contains_address_locked(const static_mempool_base* pool, const void* addr)
		{
			if (!pool || !pool->start_of_pool || !addr)
				return false;

			const auto begin = reinterpret_cast<uintptr_t>(pool->start_of_pool);
			const auto end = begin + static_cast<uint32_t>(pool->max_pool_size);
			const auto value = reinterpret_cast<uintptr_t>(addr);
			return value >= begin && value < end;
		}

		bool managed_clear_locked(static_mempool_base* pool)
		{
			if (!pool)
				return false;

			pool->pool_used = 0;
			pool->pool_used_mark = 0;
			pool->last_allocation = nullptr;
			return true;
		}

		void* managed_get_base_locked(static_mempool_base* pool)
		{
			return pool ? pool->start_of_pool : nullptr;
		}

		unsigned int managed_mark_locked(static_mempool_base* pool)
		{
			if (!pool)
				return 0;

			pool->pool_used_mark = pool->pool_used;
			return static_cast<unsigned int>(pool->pool_used_mark);
		}

		bool managed_restore_to_mark_locked(static_mempool_base* pool, unsigned int mark)
		{
			if (!pool)
				return false;

			if (mark == 0xFFFFFFFFu)
				mark = static_cast<unsigned int>(pool->pool_used_mark);

			if (mark > static_cast<uint32_t>(pool->max_pool_size))
				return false;

			pool->pool_used = static_cast<int>(mark);
			pool->pool_used_mark = static_cast<int>(mark);
			pool->last_allocation = mark ? (static_cast<uint8_t*>(pool->start_of_pool) + mark) : nullptr;
			return true;
		}

		bool managed_release_bytes_locked(static_mempool_base* pool, unsigned int bytes)
		{
			if (!pool)
				return false;

			const uint32_t used = static_cast<uint32_t>(pool->pool_used);
			if (bytes > used)
				return false;

			const int saved_mark = pool->pool_used_mark;
			const bool result = managed_restore_to_mark_locked(pool, used - bytes);
			pool->pool_used_mark = saved_mark;
			return result;
		}

		void show_effects_cpu_alloc_failure_popup(
			static_mempool_base* pool,
			uintptr_t target,
			unsigned int allocation_size,
			unsigned int alloc_alignment,
			bool needed_growth,
			bool attempted_register,
			bool register_succeeded,
			bool attempted_grow,
			bool grow_succeeded)
		{
			std::call_once(g_effects_cpu_alloc_failure_popup_once, [&]()
			{
				dynamic_pool_state state{};
				bool has_dynamic_state = false;
				{
					std::scoped_lock lock(g_dynamic_pool_mutex);
					if (const auto it = g_dynamic_pools.find(pool); it != g_dynamic_pools.end())
					{
						state = it->second;
						has_dynamic_state = true;
					}
				}

				char buffer[1024]{};
				std::snprintf(
					buffer,
					sizeof(buffer),
					"effects cpu alloc returned NULL\n\n"
					"pool=%p\n"
					"target=%p\n"
					"request_size=0x%X\n"
					"request_alignment=0x%X\n"
					"needed_growth=%d\n"
					"attempted_register=%d\n"
					"register_succeeded=%d\n"
					"attempted_grow=%d\n"
					"grow_succeeded=%d\n"
					"has_dynamic_state=%d\n"
					"pool_used=0x%X\n"
					"pool_used_mark=0x%X\n"
					"max_pool_size=0x%X\n"
					"default_alignment=0x%X\n"
					"start_of_pool=%p\n"
					"last_allocation=%p\n"
					"reserved_base=%p\n"
					"committed_size=0x%X\n"
					"reserve_size=0x%X\n"
					"grow_granularity=0x%X\n",
					pool,
					reinterpret_cast<void*>(target),
					allocation_size,
					alloc_alignment,
					needed_growth ? 1 : 0,
					attempted_register ? 1 : 0,
					register_succeeded ? 1 : 0,
					attempted_grow ? 1 : 0,
					grow_succeeded ? 1 : 0,
					has_dynamic_state ? 1 : 0,
					pool ? pool->pool_used : 0,
					pool ? pool->pool_used_mark : 0,
					pool ? pool->max_pool_size : 0,
					pool ? pool->default_alignment : 0,
					pool ? pool->start_of_pool : nullptr,
					pool ? pool->last_allocation : nullptr,
					has_dynamic_state ? state.reserved_base : nullptr,
					has_dynamic_state ? state.committed_size : 0,
					has_dynamic_state ? state.reserve_size : 0,
					has_dynamic_state ? state.grow_granularity : 0);

				MessageBoxA(nullptr, buffer, "SR2 Limit Adjuster - effects cpu alloc failed", MB_OK | MB_ICONERROR | MB_TOPMOST);
			});
		}
	}

	bool SAFETYHOOK_FASTCALL static_mempool_base_can_alloc(static_mempool_base* thisa, void* unused, unsigned int size, unsigned int alignment)
	{
		const auto target = g_static_can_alloc_target;
		const auto pool_name = get_pool_name(thisa);
		MEMPOOL_LOG("HOOK can_alloc this=%p name=%s target=%p size=0x%X alignment=0x%X used=0x%X max=0x%X start=%p\n",
			thisa,
			pool_name.empty() ? "<invalid>" : pool_name.c_str(),
			reinterpret_cast<void*>(target),
			size,
			alignment,
			thisa ? thisa->pool_used : 0,
			thisa ? thisa->max_pool_size : 0,
			thisa ? thisa->start_of_pool : nullptr);
		if (!target)
			return false;

		{
			std::scoped_lock lock(g_dynamic_pool_mutex);
			if (is_pool_managed_locked(thisa))
			{
				const auto result = managed_can_alloc_locked(thisa, size, alignment);
				MEMPOOL_LOG("HOOK can_alloc managed result this=%p name=%s result=%d used=0x%X max=0x%X\n",
					thisa,
					pool_name.empty() ? "<invalid>" : pool_name.c_str(),
					result ? 1 : 0,
					thisa ? thisa->pool_used : 0,
					thisa ? thisa->max_pool_size : 0);
				return result;
			}
		}

		if (needs_growth(thisa, size, alignment))
		{
			std::scoped_lock lock(g_dynamic_pool_mutex);
			if (!g_dynamic_pools.contains(thisa) && looks_like_supported_pool(thisa))
			{
				MEMPOOL_LOG("Auto-registering pool %s at %p from can_alloc pressure\n",
					pool_name.empty() ? "<invalid>" : pool_name.c_str(),
					thisa);
				register_pool_locked(thisa, nullptr);
			}
			if (g_dynamic_pools.contains(thisa))
				grow_pool_locked(thisa, size, alignment, "can_alloc");
		}

		const auto result = call_inline_original_thiscall<bool>(g_can_alloc_hooks, target, thisa, size, alignment);
		MEMPOOL_LOG("HOOK can_alloc result this=%p name=%s target=%p result=%d used=0x%X max=0x%X\n",
			thisa,
			pool_name.empty() ? "<invalid>" : pool_name.c_str(),
			reinterpret_cast<void*>(target),
			result ? 1 : 0,
			thisa ? thisa->pool_used : 0,
			thisa ? thisa->max_pool_size : 0);
		return result;
	}

	void* SAFETYHOOK_FASTCALL static_mempool_base_alloc(static_mempool_base* thisa, void* unused, unsigned int allocation_size, unsigned int alloc_alignment)
	{
		const auto target = g_static_alloc_target;
		const auto pool_name = get_pool_name(thisa);
		const bool is_effects_cpu = pool_name == "effects cpu";
		const bool needed_growth = needs_growth(thisa, allocation_size, alloc_alignment);
		bool attempted_register = false;
		bool register_succeeded = false;
		bool attempted_grow = false;
		bool grow_succeeded = false;
		MEMPOOL_LOG("HOOK alloc this=%p name=%s target=%p size=0x%X alignment=0x%X used=0x%X max=0x%X start=%p\n",
			thisa,
			pool_name.empty() ? "<invalid>" : pool_name.c_str(),
			reinterpret_cast<void*>(target),
			allocation_size,
			alloc_alignment,
			thisa ? thisa->pool_used : 0,
			thisa ? thisa->max_pool_size : 0,
			thisa ? thisa->start_of_pool : nullptr);
		if (!target)
			return nullptr;

		{
			std::scoped_lock lock(g_dynamic_pool_mutex);
			if (is_pool_managed_locked(thisa))
			{
				if (needed_growth)
					grow_pool_locked(thisa, allocation_size, alloc_alignment, "managed_alloc");
				auto* result = managed_alloc_locked(thisa, allocation_size, alloc_alignment);
				MEMPOOL_LOG("HOOK alloc managed result this=%p name=%s result=%p used=0x%X max=0x%X last=%p\n",
					thisa,
					pool_name.empty() ? "<invalid>" : pool_name.c_str(),
					result,
					thisa ? thisa->pool_used : 0,
					thisa ? thisa->max_pool_size : 0,
					thisa ? thisa->last_allocation : nullptr);
				return result;
			}
		}

		if (needed_growth)
		{
			std::scoped_lock lock(g_dynamic_pool_mutex);
			if (!g_dynamic_pools.contains(thisa) && looks_like_supported_pool(thisa))
			{
				attempted_register = true;
				MEMPOOL_LOG("Auto-registering pool %s at %p from alloc pressure\n",
					pool_name.empty() ? "<invalid>" : pool_name.c_str(),
					thisa);
				register_succeeded = register_pool_locked(thisa, nullptr);
			}
			if (g_dynamic_pools.contains(thisa))
			{
				attempted_grow = true;
				grow_succeeded = grow_pool_locked(thisa, allocation_size, alloc_alignment, "alloc");
			}
		}

		auto* result = call_inline_original_thiscall<void*>(g_alloc_hooks, target, thisa, allocation_size, alloc_alignment);
		if (!result && grow_succeeded)
		{
			std::scoped_lock lock(g_dynamic_pool_mutex);
			enable_managed_override_locked(thisa, "original alloc failed after successful grow");
			result = managed_alloc_locked(thisa, allocation_size, alloc_alignment);
		}
		MEMPOOL_LOG("HOOK alloc result this=%p name=%s target=%p result=%p used=0x%X max=0x%X last=%p\n",
			thisa,
			pool_name.empty() ? "<invalid>" : pool_name.c_str(),
			reinterpret_cast<void*>(target),
			result,
			thisa ? thisa->pool_used : 0,
			thisa ? thisa->max_pool_size : 0,
			thisa ? thisa->last_allocation : nullptr);
		if (is_effects_cpu && result == nullptr)
		{
			show_effects_cpu_alloc_failure_popup(
				thisa,
				target,
				allocation_size,
				alloc_alignment,
				needed_growth,
				attempted_register,
				register_succeeded,
				attempted_grow,
				grow_succeeded);
		}
		return result;
	}

	void* SAFETYHOOK_FASTCALL static_mempool_base_realloc(static_mempool_base* thisa, void* unused, void* addr_start, unsigned int new_size)
	{
		const auto target = g_static_realloc_target;
		const auto pool_name = get_pool_name(thisa);
		MEMPOOL_LOG("HOOK realloc this=%p name=%s target=%p addr=%p new_size=0x%X used=0x%X max=0x%X\n",
			thisa,
			pool_name.empty() ? "<invalid>" : pool_name.c_str(),
			reinterpret_cast<void*>(target),
			addr_start,
			new_size,
			thisa ? thisa->pool_used : 0,
			thisa ? thisa->max_pool_size : 0);
		if (!target)
			return nullptr;

		{
			std::scoped_lock lock(g_dynamic_pool_mutex);
			if (is_pool_managed_locked(thisa))
			{
				const unsigned int alignment = get_effective_alignment(thisa, 0);
				if (needs_growth(thisa, new_size, alignment))
					grow_pool_locked(thisa, new_size, alignment, "managed_realloc");
				auto* result = managed_realloc_locked(thisa, addr_start, new_size);
				MEMPOOL_LOG("HOOK realloc managed result this=%p name=%s result=%p used=0x%X max=0x%X\n",
					thisa,
					pool_name.empty() ? "<invalid>" : pool_name.c_str(),
					result,
					thisa ? thisa->pool_used : 0,
					thisa ? thisa->max_pool_size : 0);
				return result;
			}
		}

		if (void* result = call_inline_original_thiscall<void*>(g_realloc_hooks, target, thisa, addr_start, new_size))
		{
			MEMPOOL_LOG("HOOK realloc fast result this=%p name=%s target=%p result=%p used=0x%X max=0x%X\n",
				thisa,
				pool_name.empty() ? "<invalid>" : pool_name.c_str(),
				reinterpret_cast<void*>(target),
				result,
				thisa ? thisa->pool_used : 0,
				thisa ? thisa->max_pool_size : 0);
			return result;
		}

		const unsigned int alignment = get_effective_alignment(thisa, 0);
		std::scoped_lock lock(g_dynamic_pool_mutex);
		if (!g_dynamic_pools.contains(thisa) && looks_like_supported_pool(thisa))
		{
			MEMPOOL_LOG("Auto-registering pool %s at %p from realloc pressure\n",
				pool_name.empty() ? "<invalid>" : pool_name.c_str(),
				thisa);
			register_pool_locked(thisa, nullptr);
		}
		if (!g_dynamic_pools.contains(thisa) || !grow_pool_locked(thisa, new_size, alignment, "realloc"))
			return nullptr;

		auto* result = call_inline_original_thiscall<void*>(g_realloc_hooks, target, thisa, addr_start, new_size);
		if (!result)
		{
			enable_managed_override_locked(thisa, "original realloc failed after successful grow");
			result = managed_realloc_locked(thisa, addr_start, new_size);
		}
		MEMPOOL_LOG("HOOK realloc retry result this=%p name=%s target=%p result=%p used=0x%X max=0x%X\n",
			thisa,
			pool_name.empty() ? "<invalid>" : pool_name.c_str(),
			reinterpret_cast<void*>(target),
			result,
			thisa ? thisa->pool_used : 0,
			thisa ? thisa->max_pool_size : 0);
		return result;
	}

	bool SAFETYHOOK_FASTCALL static_mempool_contains_address(static_mempool_base* thisa, void* unused, void* addr)
	{
		const auto target = g_static_contains_address_target;
		const auto pool_name = get_pool_name(thisa);
		if (!target)
			return false;

		std::scoped_lock lock(g_dynamic_pool_mutex);
		if (is_pool_managed_locked(thisa))
		{
			const auto result = managed_contains_address_locked(thisa, addr);
			MEMPOOL_LOG("HOOK contains_address managed result this=%p name=%s addr=%p result=%d\n",
				thisa,
				pool_name.empty() ? "<invalid>" : pool_name.c_str(),
				addr,
				result ? 1 : 0);
			return result;
		}

		return call_inline_original_thiscall<bool>(g_contains_address_hooks, target, thisa, addr);
	}

	bool SAFETYHOOK_FASTCALL static_mempool_clear(static_mempool_base* thisa, void* unused)
	{
		const auto target = g_static_clear_target;
		const auto pool_name = get_pool_name(thisa);
		if (!target)
			return false;

		std::scoped_lock lock(g_dynamic_pool_mutex);
		if (is_pool_managed_locked(thisa))
		{
			const auto result = managed_clear_locked(thisa);
			MEMPOOL_LOG("HOOK clear managed result this=%p name=%s result=%d\n",
				thisa,
				pool_name.empty() ? "<invalid>" : pool_name.c_str(),
				result ? 1 : 0);
			return result;
		}

		return call_inline_original_thiscall<bool>(g_clear_hooks, target, thisa);
	}

	void* SAFETYHOOK_FASTCALL static_mempool_get_base(static_mempool_base* thisa, void* unused)
	{
		const auto target = g_static_get_base_target;
		if (!target)
			return nullptr;

		std::scoped_lock lock(g_dynamic_pool_mutex);
		if (is_pool_managed_locked(thisa))
			return managed_get_base_locked(thisa);

		return call_inline_original_thiscall<void*>(g_get_base_hooks, target, thisa);
	}

	unsigned int SAFETYHOOK_FASTCALL static_mempool_mark(static_mempool_base* thisa, void* unused)
	{
		const auto target = g_static_mark_target;
		const auto pool_name = get_pool_name(thisa);
		if (!target)
			return 0;

		std::scoped_lock lock(g_dynamic_pool_mutex);
		if (is_pool_managed_locked(thisa))
		{
			const auto result = managed_mark_locked(thisa);
			MEMPOOL_LOG("HOOK mark managed result this=%p name=%s result=0x%X\n",
				thisa,
				pool_name.empty() ? "<invalid>" : pool_name.c_str(),
				result);
			return result;
		}

		return call_inline_original_thiscall<unsigned int>(g_mark_hooks, target, thisa);
	}

	bool SAFETYHOOK_FASTCALL static_mempool_restore_to_mark(static_mempool_base* thisa, void* unused, unsigned int mark)
	{
		const auto target = g_static_restore_to_mark_target;
		const auto pool_name = get_pool_name(thisa);
		if (!target)
			return false;

		std::scoped_lock lock(g_dynamic_pool_mutex);
		if (is_pool_managed_locked(thisa))
		{
			const auto result = managed_restore_to_mark_locked(thisa, mark);
			MEMPOOL_LOG("HOOK restore_to_mark managed result this=%p name=%s mark=0x%X result=%d used=0x%X\n",
				thisa,
				pool_name.empty() ? "<invalid>" : pool_name.c_str(),
				mark,
				result ? 1 : 0,
				thisa ? thisa->pool_used : 0);
			return result;
		}

		return call_inline_original_thiscall<bool>(g_restore_to_mark_hooks, target, thisa, mark);
	}

	bool SAFETYHOOK_FASTCALL static_mempool_release_bytes(static_mempool_base* thisa, void* unused, unsigned int bytes)
	{
		const auto target = g_static_release_bytes_target;
		const auto pool_name = get_pool_name(thisa);
		if (!target)
			return false;

		std::scoped_lock lock(g_dynamic_pool_mutex);
		if (is_pool_managed_locked(thisa))
		{
			const auto result = managed_release_bytes_locked(thisa, bytes);
			MEMPOOL_LOG("HOOK release_bytes managed result this=%p name=%s bytes=0x%X result=%d used=0x%X mark=0x%X\n",
				thisa,
				pool_name.empty() ? "<invalid>" : pool_name.c_str(),
				bytes,
				result ? 1 : 0,
				thisa ? thisa->pool_used : 0,
				thisa ? thisa->pool_used_mark : 0);
			return result;
		}

		return call_inline_original_thiscall<bool>(g_release_bytes_hooks, target, thisa, bytes);
	}

	bool SAFETYHOOK_FASTCALL static_mempool_pad_to_page(static_mempool_base* thisa, void* unused, unsigned int alignment)
	{
		const auto target = g_static_pad_to_page_target;
		const auto pool_name = get_pool_name(thisa);
		MEMPOOL_LOG("HOOK pad_to_page this=%p name=%s target=%p alignment=0x%X used=0x%X max=0x%X\n",
			thisa,
			pool_name.empty() ? "<invalid>" : pool_name.c_str(),
			reinterpret_cast<void*>(target),
			alignment,
			thisa ? thisa->pool_used : 0,
			thisa ? thisa->max_pool_size : 0);
		if (!target)
			return false;

		{
			std::scoped_lock lock(g_dynamic_pool_mutex);
			if (is_pool_managed_locked(thisa))
			{
				if (needs_growth(thisa, 0, alignment))
				{
					const uint32_t page_alignment = (std::max)(g_page_size, get_effective_alignment(thisa, alignment));
					const uint32_t padded_used = align_up(static_cast<uint32_t>(thisa->pool_used), page_alignment);
					if (padded_used > static_cast<uint32_t>(thisa->max_pool_size))
						grow_pool_locked(thisa, padded_used - static_cast<uint32_t>(thisa->pool_used), page_alignment, "managed_pad_to_page");
				}
				const auto result = managed_pad_to_page_locked(thisa, alignment);
				MEMPOOL_LOG("HOOK pad_to_page managed result this=%p name=%s result=%d used=0x%X max=0x%X\n",
					thisa,
					pool_name.empty() ? "<invalid>" : pool_name.c_str(),
					result ? 1 : 0,
					thisa ? thisa->pool_used : 0,
					thisa ? thisa->max_pool_size : 0);
				return result;
			}
		}

		if (needs_growth(thisa, 0, alignment))
		{
			const uint32_t page_alignment = (std::max)(g_page_size, get_effective_alignment(thisa, alignment));
			const uint32_t padded_used = align_up(static_cast<uint32_t>(thisa->pool_used), page_alignment);
			if (padded_used > static_cast<uint32_t>(thisa->max_pool_size))
			{
				std::scoped_lock lock(g_dynamic_pool_mutex);
				if (!g_dynamic_pools.contains(thisa) && looks_like_supported_pool(thisa))
				{
					MEMPOOL_LOG("Auto-registering pool %s at %p from pad_to_page pressure\n",
						pool_name.empty() ? "<invalid>" : pool_name.c_str(),
						thisa);
					register_pool_locked(thisa, nullptr);
				}
				if (g_dynamic_pools.contains(thisa))
					grow_pool_locked(thisa, padded_used - static_cast<uint32_t>(thisa->pool_used), page_alignment, "pad_to_page");
			}
		}

		const auto result = call_inline_original_thiscall<bool>(g_pad_to_page_hooks, target, thisa, alignment);
		MEMPOOL_LOG("HOOK pad_to_page result this=%p name=%s target=%p result=%d used=0x%X max=0x%X\n",
			thisa,
			pool_name.empty() ? "<invalid>" : pool_name.c_str(),
			reinterpret_cast<void*>(target),
			result ? 1 : 0,
			thisa ? thisa->pool_used : 0,
			thisa ? thisa->max_pool_size : 0);
		return result;
	}

	bool RegisterGrowableMempool(static_mempool_base* pool, const DynamicMempoolConfig& config)
	{
		if (!pool)
			return false;
		std::scoped_lock lock(g_dynamic_pool_mutex);
		const auto pool_name = get_pool_name(pool);
		MEMPOOL_LOG("RegisterGrowableMempool pool=%p name=%s\n",
			pool,
			pool_name.empty() ? "<invalid>" : pool_name.c_str());
		return register_pool_locked(pool, &config);
	}

	using string_pool_add_unique_base_abi = uc::abi<
		uc::eax_ret<char*>,
		uc::eax_arg<string_pool*>,
		uc::stack_arg<const char*>
	>;



	static uc::inline_hook_callee<string_pool_add_unique_base_abi> string_pool_add_unique_hook;

	char* SAFETYHOOK_CCALL string_pool_add_unqiue_detour(string_pool* thisa, const char* string)
	{
		auto result = string_pool_add_unique_hook.unsafe_call_original(thisa, string);
		if (!result)
		{
			auto fallback = const_cast<char*>(get_or_create_string_pool_fallback(string));
			MEMPOOL_LOG("string_pool::add_unique fallback this=%p src=%s result=%p\n",
				thisa,
				string ? string : "<null>",
				fallback);
			return fallback;
		}
		return result;
	}

	void Mempool_init()
	{
		CIniReader ini;

		if (ini.ReadInteger("EXPERIMENTAL", "DynamicStringMempools", 1))
		{
			string_pool_add_unique_hook.create(0xC06EE0_g, string_pool_add_unqiue_detour);
		}

		if (ini.ReadInteger("EXPERIMENTAL", "DynamicMempools", 1) == 0)
			return;

		if (g_mempool_hooks_installed)
			return;

		SYSTEM_INFO system_info{};
		GetSystemInfo(&system_info);
		if (system_info.dwPageSize)
			g_page_size = system_info.dwPageSize;

		const auto static_vtable = Memory::DynBaseAddress(kRetailStaticMempoolVtbl);
		const auto mempool_vtable = Memory::DynBaseAddress(kRetailMempoolVtbl);

		g_static_can_alloc_target = reinterpret_cast<uintptr_t>(read_vtable_entry<void*>(static_vtable, 7));
		g_static_alloc_target = reinterpret_cast<uintptr_t>(read_vtable_entry<void*>(static_vtable, 8));
		g_static_realloc_target = reinterpret_cast<uintptr_t>(read_vtable_entry<void*>(static_vtable, 9));
		g_static_contains_address_target = reinterpret_cast<uintptr_t>(read_vtable_entry<void*>(static_vtable, 10));
		g_static_clear_target = reinterpret_cast<uintptr_t>(read_vtable_entry<void*>(static_vtable, 11));
		g_static_get_base_target = reinterpret_cast<uintptr_t>(read_vtable_entry<void*>(static_vtable, 12));
		g_static_mark_target = reinterpret_cast<uintptr_t>(read_vtable_entry<void*>(static_vtable, 13));
		g_static_restore_to_mark_target = reinterpret_cast<uintptr_t>(read_vtable_entry<void*>(static_vtable, 14));
		g_static_release_bytes_target = reinterpret_cast<uintptr_t>(read_vtable_entry<void*>(static_vtable, 15));
		g_static_pad_to_page_target = reinterpret_cast<uintptr_t>(read_vtable_entry<void*>(static_vtable, 16));

		install_deduped_inline_hook(g_can_alloc_hooks, g_static_can_alloc_target, static_mempool_base_can_alloc, "static_mempool_base::can_alloc");
		install_deduped_inline_hook(g_alloc_hooks, g_static_alloc_target, static_mempool_base_alloc, "static_mempool_base::alloc");
		install_deduped_inline_hook(g_realloc_hooks, g_static_realloc_target, static_mempool_base_realloc, "static_mempool_base::realloc");
		install_deduped_inline_hook(g_contains_address_hooks, g_static_contains_address_target, static_mempool_contains_address, "static_mempool_base::contains_address");
		install_deduped_inline_hook(g_clear_hooks, g_static_clear_target, static_mempool_clear, "static_mempool_base::clear");
		install_deduped_inline_hook(g_get_base_hooks, g_static_get_base_target, static_mempool_get_base, "static_mempool_base::get_base");
		install_deduped_inline_hook(g_mark_hooks, g_static_mark_target, static_mempool_mark, "static_mempool_base::mark");
		install_deduped_inline_hook(g_restore_to_mark_hooks, g_static_restore_to_mark_target, static_mempool_restore_to_mark, "static_mempool_base::restore_to_mark");
		install_deduped_inline_hook(g_release_bytes_hooks, g_static_release_bytes_target, static_mempool_release_bytes, "static_mempool_base::release_bytes");
		install_deduped_inline_hook(g_pad_to_page_hooks, g_static_pad_to_page_target, static_mempool_pad_to_page, "static_mempool_base::pad_to_page");

		g_mempool_hooks_installed = true;
		MEMPOOL_LOG("Installed inline mempool hooks: static_vft=%p mempool_vft=%p page=0x%X alloc=%p realloc=%p contains=%p clear=%p get_base=%p mark=%p restore=%p release=%p pad=%p\n",
			reinterpret_cast<void*>(static_vtable),
			reinterpret_cast<void*>(mempool_vtable),
			g_page_size,
			reinterpret_cast<void*>(g_static_alloc_target),
			reinterpret_cast<void*>(g_static_realloc_target),
			reinterpret_cast<void*>(g_static_contains_address_target),
			reinterpret_cast<void*>(g_static_clear_target),
			reinterpret_cast<void*>(g_static_get_base_target),
			reinterpret_cast<void*>(g_static_mark_target),
			reinterpret_cast<void*>(g_static_restore_to_mark_target),
			reinterpret_cast<void*>(g_static_release_bytes_target),
			reinterpret_cast<void*>(g_static_pad_to_page_target));
	}
}
