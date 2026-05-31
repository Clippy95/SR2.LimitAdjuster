#include "pch.h"
#include "ExtendedSaves.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <string>
#include <unordered_map>
#include <vector>

#include "sr_xml.h"
#define UC_WITH_SAFETYHOOK
#include "usercaller/safetyhook_inline.hpp"

void lprintf(const char* format, ...);

namespace ExtendedSaves
{
    namespace
    {
        inline constexpr std::uint32_t kSaveExtMagic = 0x58453253; // "S2EX"
        inline constexpr std::uint32_t kSaveExtVersion = 1;

        inline char* g_LocalAppdataSavePath = reinterpret_cast<char*>(0x144E650_g);

        using SaveWriterAbi = uc::abi<
            uc::eax_ret<bool>,
            uc::ecx_arg<const char*>,
            uc::stack_arg<char*>>;

        using SaveLoaderAbi = uc::abi<
            uc::eax_ret<bool>,
            uc::stack_arg<void**>,
            uc::stack_arg<const char*>>;

#pragma pack(push, 1)
        struct SaveExtChunkHeader
        {
            std::uint32_t tag;
            std::uint32_t version;
            std::uint32_t size;
        };

        struct SaveExtFooter
        {
            std::uint32_t magic;
            std::uint32_t version;
            std::uint32_t ext_size;
            std::uint32_t chunk_count;
        };
#pragma pack(pop)

        struct RuntimeChunk
        {
            std::uint32_t tag{};
            std::uint32_t version{};
            std::vector<std::uint8_t> payload{};
        };

        static std::mutex g_ExtMutex;
        static std::unordered_map<std::uint32_t, RuntimeChunk> g_Chunks;
        static std::vector<SaveWriteCallback> g_BeforeSaveCallbacks;
        static std::vector<SaveLoadCallback> g_AfterLoadCallbacks;
        static uc::inline_hook<SaveWriterAbi> g_SaveWriterHook;
        static uc::inline_hook<SaveLoaderAbi> g_SaveLoaderHook;
        static bool g_HooksInstalled = false;

        std::filesystem::path BuildSavePath(const char* save_name)
        {
            if (!save_name || !*save_name || !g_LocalAppdataSavePath || !*g_LocalAppdataSavePath)
                return {};

            std::filesystem::path path(g_LocalAppdataSavePath);
            path /= std::string(save_name) + ".bbsave";
            return path;
        }

        std::vector<const RuntimeChunk*> GetChunksInSaveOrder()
        {
            std::vector<const RuntimeChunk*> ordered;
            ordered.reserve(g_Chunks.size());

            for (const auto& [tag, chunk] : g_Chunks)
            {
                (void)tag;
                ordered.push_back(&chunk);
            }

            std::sort(
                ordered.begin(),
                ordered.end(),
                [](const RuntimeChunk* lhs, const RuntimeChunk* rhs)
                {
                    return lhs->tag < rhs->tag;
                });

            return ordered;
        }

        std::vector<std::uint8_t> BuildSerializedExtensionLocked()
        {
            const auto ordered = GetChunksInSaveOrder();

            std::uint32_t ext_payload_size = 0;
            for (const RuntimeChunk* chunk : ordered)
            {
                ext_payload_size += static_cast<std::uint32_t>(sizeof(SaveExtChunkHeader));
                ext_payload_size += static_cast<std::uint32_t>(chunk->payload.size());
            }

            std::vector<std::uint8_t> bytes;
            bytes.reserve(ext_payload_size + sizeof(SaveExtFooter));

            for (const RuntimeChunk* chunk : ordered)
            {
                const SaveExtChunkHeader header{
                    chunk->tag,
                    chunk->version,
                    static_cast<std::uint32_t>(chunk->payload.size())
                };

                const auto header_begin = reinterpret_cast<const std::uint8_t*>(&header);
                bytes.insert(bytes.end(), header_begin, header_begin + sizeof(header));
                bytes.insert(bytes.end(), chunk->payload.begin(), chunk->payload.end());
            }

            const SaveExtFooter footer{
                kSaveExtMagic,
                kSaveExtVersion,
                ext_payload_size,
                static_cast<std::uint32_t>(ordered.size())
            };

            const auto footer_begin = reinterpret_cast<const std::uint8_t*>(&footer);
            bytes.insert(bytes.end(), footer_begin, footer_begin + sizeof(footer));
            return bytes;
        }

        void ClearLocked()
        {
            g_Chunks.clear();
        }

        void RunBeforeSaveCallbacks(const char* save_name)
        {
            std::vector<SaveWriteCallback> callbacks;
            {
                std::scoped_lock lock(g_ExtMutex);
                callbacks = g_BeforeSaveCallbacks;
            }

            for (const auto callback : callbacks)
            {
                if (callback)
                    callback(save_name);
            }
        }

        void RunAfterLoadCallbacks(const char* save_name, bool has_extension)
        {
            std::vector<SaveLoadCallback> callbacks;
            {
                std::scoped_lock lock(g_ExtMutex);
                callbacks = g_AfterLoadCallbacks;
            }

            for (const auto callback : callbacks)
            {
                if (callback)
                    callback(save_name, has_extension);
            }
        }

        bool ParseSerializedExtension(const std::uint8_t* file_bytes, std::size_t file_size)
        {
            std::scoped_lock lock(g_ExtMutex);
            ClearLocked();

            if (!file_bytes || file_size <= kVanillaSerializedSize + sizeof(SaveExtFooter))
                return false;

            const auto* footer = reinterpret_cast<const SaveExtFooter*>(
                file_bytes + file_size - sizeof(SaveExtFooter));

            if (footer->magic != kSaveExtMagic || footer->version != kSaveExtVersion)
                return false;

            const std::size_t max_ext_bytes = file_size - kVanillaSerializedSize - sizeof(SaveExtFooter);
            if (footer->ext_size > max_ext_bytes)
            {
                lprintf("ExtendedSaves: footer ext_size 0x%X exceeds trailing bytes 0x%zX, ignoring extension.\n",
                    footer->ext_size, max_ext_bytes);
                return false;
            }

            const std::size_t ext_start = file_size - sizeof(SaveExtFooter) - footer->ext_size;
            if (ext_start != kVanillaSerializedSize)
            {
                lprintf("ExtendedSaves: extension starts at 0x%zX instead of 0x%X, ignoring extension.\n",
                    ext_start, kVanillaSerializedSize);
                return false;
            }

            const std::uint8_t* cursor = file_bytes + ext_start;
            const std::uint8_t* const footer_bytes = file_bytes + file_size - sizeof(SaveExtFooter);

            for (std::uint32_t index = 0; index < footer->chunk_count; ++index)
            {
                if (cursor + sizeof(SaveExtChunkHeader) > footer_bytes)
                {
                    ClearLocked();
                    lprintf("ExtendedSaves: chunk header overflow while parsing extension.\n");
                    return false;
                }

                const auto* header = reinterpret_cast<const SaveExtChunkHeader*>(cursor);
                cursor += sizeof(SaveExtChunkHeader);

                if (cursor + header->size > footer_bytes)
                {
                    ClearLocked();
                    lprintf("ExtendedSaves: chunk 0x%08X size 0x%X overruns extension payload.\n",
                        header->tag, header->size);
                    return false;
                }

                RuntimeChunk chunk{};
                chunk.tag = header->tag;
                chunk.version = header->version;
                chunk.payload.assign(cursor, cursor + header->size);
                g_Chunks[chunk.tag] = std::move(chunk);

                cursor += header->size;
            }

            if (cursor != footer_bytes)
            {
                ClearLocked();
                lprintf("ExtendedSaves: leftover bytes detected while parsing extension, ignoring save extension.\n");
                return false;
            }

            if (!g_Chunks.empty())
                lprintf("ExtendedSaves: loaded %u chunk(s) from save extension.\n", static_cast<unsigned>(g_Chunks.size()));

            return !g_Chunks.empty();
        }

        bool RewriteSaveWithExtension(const char* save_name, const char* save_game_ptr)
        {
            std::vector<std::uint8_t> ext_bytes;
            {
                std::scoped_lock lock(g_ExtMutex);
                if (g_Chunks.empty())
                    return true;

                ext_bytes = BuildSerializedExtensionLocked();
            }

            const std::uint32_t total_size = kVanillaSerializedSize + static_cast<std::uint32_t>(ext_bytes.size());
            if (total_size > kSafePerSaveFileSize)
            {
                lprintf("ExtendedSaves: refusing to write 0x%X-byte save, safe load cap is 0x%X.\n",
                    total_size, kSafePerSaveFileSize);
                return false;
            }

            const std::filesystem::path save_path = BuildSavePath(save_name);
            if (save_path.empty())
            {
                lprintf("ExtendedSaves: save path was empty, skipping extension rewrite.\n");
                return false;
            }

            std::ofstream file(save_path, std::ios::binary | std::ios::trunc);
            if (!file.is_open())
            {
                lprintf("ExtendedSaves: failed to reopen %s for extended write.\n", save_path.string().c_str());
                return false;
            }

            file.write(save_game_ptr, kVanillaSerializedSize);
            if (!ext_bytes.empty())
                file.write(reinterpret_cast<const char*>(ext_bytes.data()), static_cast<std::streamsize>(ext_bytes.size()));

            if (!file.good())
            {
                lprintf("ExtendedSaves: failed while writing extension to %s.\n", save_path.string().c_str());
                return false;
            }

            lprintf("ExtendedSaves: wrote %u chunk(s), total file size 0x%X.\n",
                GetCurrentChunkCount(),
                total_size);
            return true;
        }

        bool PreloadSaveExtension(const char* save_name)
        {
            Clear();

            const std::filesystem::path save_path = BuildSavePath(save_name);
            std::error_code ec;
            const std::uintmax_t file_size = save_path.empty() ? 0 : std::filesystem::file_size(save_path, ec);
            if (ec || file_size <= kVanillaSerializedSize)
                return false;

            std::ifstream file(save_path, std::ios::binary);
            if (!file.is_open())
            {
                lprintf("ExtendedSaves: failed to open %s for extension preload.\n", save_path.string().c_str());
                return false;
            }

            std::vector<std::uint8_t> file_bytes(static_cast<std::size_t>(file_size));
            file.read(reinterpret_cast<char*>(file_bytes.data()), static_cast<std::streamsize>(file_bytes.size()));
            if (!file.good() && !file.eof())
            {
                lprintf("ExtendedSaves: failed while reading %s for extension preload.\n", save_path.string().c_str());
                Clear();
                return false;
            }

            return ParseSerializedExtension(file_bytes.data(), file_bytes.size());
        }

        bool UC_CDECL SaveWriterHook(const char* save_name, char* save_game_ptr)
        {
            RunBeforeSaveCallbacks(save_name);
            const bool result = g_SaveWriterHook.call_original(save_name, save_game_ptr);
            if (!result || !save_game_ptr)
                return result;

            RewriteSaveWithExtension(save_name, save_game_ptr);
            return result;
        }

        bool UC_CDECL SaveLoaderHook(void** save_game_ptr, const char* save_name)
        {
            const bool has_extension = PreloadSaveExtension(save_name);
            const bool result = g_SaveLoaderHook.call_original(save_game_ptr, save_name);
            if (!result || !save_game_ptr || !*save_game_ptr)
            {
                Clear();
                RunAfterLoadCallbacks(save_name, false);
                return result;
            }

            RunAfterLoadCallbacks(save_name, has_extension);
            return result;
        }
    }

    void InstallHooks()
    {
        if (g_HooksInstalled)
            return;

        const bool writer_installed = g_SaveWriterHook.create(0x6951B0_g, SaveWriterHook);
        const bool loader_installed = g_SaveLoaderHook.create(0x691E10_g, SaveLoaderHook);

        g_HooksInstalled = writer_installed && loader_installed;
        lprintf("ExtendedSaves: writer hook %s, loader hook %s.\n",
            writer_installed ? "installed" : "failed",
            loader_installed ? "installed" : "failed");
    }

    void Clear()
    {
        std::scoped_lock lock(g_ExtMutex);
        ClearLocked();
    }

    void RegisterBeforeSaveCallback(SaveWriteCallback callback)
    {
        if (!callback)
            return;

        std::scoped_lock lock(g_ExtMutex);
        if (std::find(g_BeforeSaveCallbacks.begin(), g_BeforeSaveCallbacks.end(), callback) == g_BeforeSaveCallbacks.end())
            g_BeforeSaveCallbacks.push_back(callback);
    }

    void RegisterAfterLoadCallback(SaveLoadCallback callback)
    {
        if (!callback)
            return;

        std::scoped_lock lock(g_ExtMutex);
        if (std::find(g_AfterLoadCallbacks.begin(), g_AfterLoadCallbacks.end(), callback) == g_AfterLoadCallbacks.end())
            g_AfterLoadCallbacks.push_back(callback);
    }

    std::uint32_t MakeTag(const char* name)
    {
        if (!name || !*name)
            return 0;

        return str_to_hash(name);
    }

    std::uint32_t MakeTag(std::string_view name)
    {
        if (name.empty())
            return 0;

        std::string buffer(name);
        return MakeTag(buffer.c_str());
    }

    bool HasChunk(std::uint32_t tag)
    {
        std::scoped_lock lock(g_ExtMutex);
        return g_Chunks.find(tag) != g_Chunks.end();
    }

    ChunkView GetChunk(std::uint32_t tag)
    {
        std::scoped_lock lock(g_ExtMutex);

        const auto it = g_Chunks.find(tag);
        if (it == g_Chunks.end())
            return {};

        const RuntimeChunk& chunk = it->second;
        return {
            true,
            chunk.payload.empty() ? nullptr : chunk.payload.data(),
            static_cast<std::uint32_t>(chunk.payload.size()),
            chunk.version
        };
    }

    ChunkView GetChunk(const char* name)
    {
        return GetChunk(MakeTag(name));
    }

    bool SetChunk(std::uint32_t tag, const void* data, std::uint32_t size, std::uint32_t version)
    {
        if (!tag || (size && !data))
            return false;

        RuntimeChunk chunk{};
        chunk.tag = tag;
        chunk.version = version;
        chunk.payload.resize(size);

        if (size)
            std::memcpy(chunk.payload.data(), data, size);

        std::scoped_lock lock(g_ExtMutex);
        g_Chunks[tag] = std::move(chunk);
        return true;
    }

    bool SetChunk(const char* name, const void* data, std::uint32_t size, std::uint32_t version)
    {
        return SetChunk(MakeTag(name), data, size, version);
    }

    bool RemoveChunk(std::uint32_t tag)
    {
        std::scoped_lock lock(g_ExtMutex);
        return g_Chunks.erase(tag) != 0;
    }

    bool RemoveChunk(const char* name)
    {
        return RemoveChunk(MakeTag(name));
    }

    std::uint32_t GetCurrentChunkCount()
    {
        std::scoped_lock lock(g_ExtMutex);
        return static_cast<std::uint32_t>(g_Chunks.size());
    }

    std::uint32_t GetSerializedExtensionSize()
    {
        std::scoped_lock lock(g_ExtMutex);
        if (g_Chunks.empty())
            return 0;

        const auto bytes = BuildSerializedExtensionLocked();
        return static_cast<std::uint32_t>(bytes.size());
    }
}
