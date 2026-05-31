#pragma once

#include <cstdint>
#include <string_view>
#include <type_traits>

namespace ExtendedSaves
{
    inline constexpr std::uint32_t kVanillaSerializedSize = 0x3AB58;
    inline constexpr std::uint32_t kSafePerSaveFileSize = 0x100000;
    using SaveWriteCallback = void(*)(const char* save_name);
    using SaveLoadCallback = void(*)(const char* save_name, bool has_extension);

    struct ChunkView
    {
        bool present{};
        const std::uint8_t* data{};
        std::uint32_t size{};
        std::uint32_t version{};

        explicit operator bool() const noexcept
        {
            return present;
        }
    };

    void InstallHooks();
    void Clear();
    void RegisterBeforeSaveCallback(SaveWriteCallback callback);
    void RegisterAfterLoadCallback(SaveLoadCallback callback);

    std::uint32_t MakeTag(const char* name);
    std::uint32_t MakeTag(std::string_view name);

    bool HasChunk(std::uint32_t tag);
    ChunkView GetChunk(std::uint32_t tag);
    ChunkView GetChunk(const char* name);

    bool SetChunk(std::uint32_t tag, const void* data, std::uint32_t size, std::uint32_t version = 1);
    bool SetChunk(const char* name, const void* data, std::uint32_t size, std::uint32_t version = 1);

    bool RemoveChunk(std::uint32_t tag);
    bool RemoveChunk(const char* name);

    std::uint32_t GetCurrentChunkCount();
    std::uint32_t GetSerializedExtensionSize();
    bool IsLoadInProgress();

    template <typename T>
    const T* GetPod(std::uint32_t tag)
    {
        static_assert(std::is_trivially_copyable_v<T>, "Extended save POD helpers require trivially copyable types.");

        const ChunkView view = GetChunk(tag);
        if (!view.data || view.size != sizeof(T))
            return nullptr;

        return reinterpret_cast<const T*>(view.data);
    }

    template <typename T>
    const T* GetPod(const char* name)
    {
        return GetPod<T>(MakeTag(name));
    }

    template <typename T>
    bool SetPod(std::uint32_t tag, const T& value, std::uint32_t version = 1)
    {
        static_assert(std::is_trivially_copyable_v<T>, "Extended save POD helpers require trivially copyable types.");
        return SetChunk(tag, &value, static_cast<std::uint32_t>(sizeof(T)), version);
    }

    template <typename T>
    bool SetPod(const char* name, const T& value, std::uint32_t version = 1)
    {
        return SetPod(MakeTag(name), value, version);
    }
}
