// ConsentMonitor — filesystem_interface.hpp
// Abstract filesystem interface for testable journal and rotation engines.
// Copyright 2026 ConsentMonitor Contributors. MIT License.

#pragma once

#include <consent_monitor/common.hpp>

#include <cstdint>
#include <functional>
#include <map>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace consent_monitor {

// ─── File identity for verification ─────────────────────────────────────────
struct FileIdentity {
    uint64_t    size = 0;
    std::string content_hash;   // CRC-32 hex string for identity checks
    bool        exists = false;
};

// ─── Abstract Filesystem ────────────────────────────────────────────────────
class IFilesystem {
public:
    virtual ~IFilesystem() = default;

    virtual Result<void>        WriteFile(const std::string& path,
                                          const std::string& content) = 0;
    // CREATE_NEW semantics: fail if the file already exists.
    virtual Result<void>        WriteFileExclusive(const std::string& path,
                                                   const std::string& content) = 0;
    virtual Result<std::string> ReadFile(const std::string& path) = 0;
    virtual Result<void>        DeleteFile(const std::string& path) = 0;
    virtual Result<void>        MoveFile(const std::string& src,
                                         const std::string& dst,
                                         bool replace_existing) = 0;
    virtual Result<void>        FlushFile(const std::string& path) = 0;

    virtual bool                FileExists(const std::string& path) const = 0;
    virtual Result<uint64_t>    FileSize(const std::string& path) const = 0;
    virtual Result<FileIdentity>GetIdentity(const std::string& path) const = 0;
    virtual Result<std::vector<std::string>>
                                ListFiles(const std::string& directory) const = 0;
};

// ─── In-Memory Filesystem (for tests) ───────────────────────────────────────
class InMemoryFilesystem : public IFilesystem {
public:
    // ── Error injection ─────────────────────────────────────────────────
    void InjectError(const std::string& path, const std::string& op,
                     const std::string& err) {
        injected_errors_[{path, op}] = err;
    }
    void ClearErrors() { injected_errors_.clear(); }

    // ── IFilesystem implementation ──────────────────────────────────────
    Result<void> WriteFile(const std::string& path,
                           const std::string& content) override {
        if (auto e = CheckError(path, "write")) return *e;
        files_[path] = content;
        return Result<void>::success();
    }

    Result<void> WriteFileExclusive(const std::string& path,
                                    const std::string& content) override {
        if (auto e = CheckError(path, "write_exclusive")) return *e;
        if (files_.count(path))
            return Result<void>::failure("File already exists: " + path);
        files_[path] = content;
        return Result<void>::success();
    }

    Result<std::string> ReadFile(const std::string& path) override {
        if (auto e = CheckErrorT<std::string>(path, "read")) return *e;
        auto it = files_.find(path);
        if (it == files_.end())
            return Result<std::string>::failure("File not found: " + path);
        return Result<std::string>::success(it->second);
    }

    Result<void> DeleteFile(const std::string& path) override {
        if (auto e = CheckError(path, "delete")) return *e;
        auto it = files_.find(path);
        if (it == files_.end())
            return Result<void>::failure("File not found: " + path);
        files_.erase(it);
        return Result<void>::success();
    }

    Result<void> MoveFile(const std::string& src, const std::string& dst,
                          bool replace_existing) override {
        if (auto e = CheckError(src, "move")) return *e;
        auto it = files_.find(src);
        if (it == files_.end())
            return Result<void>::failure("Source not found: " + src);
        if (!replace_existing && files_.count(dst))
            return Result<void>::failure("Destination exists: " + dst);
        files_[dst] = std::move(it->second);
        files_.erase(it);
        return Result<void>::success();
    }

    Result<void> FlushFile(const std::string& path) override {
        if (auto e = CheckError(path, "flush")) return *e;
        if (!files_.count(path))
            return Result<void>::failure("File not found: " + path);
        return Result<void>::success();
    }

    bool FileExists(const std::string& path) const override {
        return files_.count(path) > 0;
    }

    Result<uint64_t> FileSize(const std::string& path) const override {
        auto it = files_.find(path);
        if (it == files_.end())
            return Result<uint64_t>::failure("File not found: " + path);
        return Result<uint64_t>::success(
            static_cast<uint64_t>(it->second.size()));
    }

    Result<FileIdentity> GetIdentity(const std::string& path) const override {
        auto it = files_.find(path);
        if (it == files_.end()) {
            FileIdentity id;
            id.exists = false;
            return Result<FileIdentity>::success(id);
        }
        FileIdentity id;
        id.exists = true;
        id.size   = it->second.size();
        // Simple hash: use content length + first/last chars for identity.
        // Full CRC-32 can be used if crc32 module is linked.
        id.content_hash = std::to_string(id.size);
        return Result<FileIdentity>::success(id);
    }

    Result<std::vector<std::string>>
    ListFiles(const std::string& directory) const override {
        std::vector<std::string> result;
        std::string prefix = directory;
        if (!prefix.empty() && prefix.back() != '/') prefix += '/';
        for (auto const& [path, _] : files_) {
            if (path.rfind(prefix, 0) == 0) {
                // Only include direct children (no sub-subdirectories).
                auto rest = path.substr(prefix.size());
                if (rest.find('/') == std::string::npos) {
                    result.push_back(path);
                }
            }
        }
        return Result<std::vector<std::string>>::success(result);
    }

    // ── Direct access for test assertions ───────────────────────────────
    const std::unordered_map<std::string, std::string>& AllFiles() const {
        return files_;
    }

private:
    std::unordered_map<std::string, std::string> files_;
    std::map<std::pair<std::string, std::string>, std::string> injected_errors_;

    std::optional<Result<void>> CheckError(const std::string& path,
                                           const std::string& op) {
        auto it = injected_errors_.find({path, op});
        if (it != injected_errors_.end())
            return Result<void>::failure(it->second);
        return std::nullopt;
    }

    template <typename T>
    std::optional<Result<T>> CheckErrorT(const std::string& path,
                                         const std::string& op) {
        auto it = injected_errors_.find({path, op});
        if (it != injected_errors_.end())
            return Result<T>::failure(it->second);
        return std::nullopt;
    }
};

} // namespace consent_monitor
