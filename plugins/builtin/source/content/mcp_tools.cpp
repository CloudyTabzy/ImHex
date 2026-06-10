#include <content/providers/file_provider.hpp>
#include <hex/api/content_registry/communication_interface.hpp>
#include <hex/api/imhex_api/provider.hpp>
#include <hex/api/imhex_api/bookmarks.hpp>
#include <hex/api/task_manager.hpp>
#include <hex/helpers/crypto.hpp>
#include <hex/helpers/fmt.hpp>
#include <hex/helpers/utils.hpp>
#include <hex/providers/provider.hpp>
#include <romfs/romfs.hpp>
#include <wolv/literals.hpp>

#include <nlohmann/json.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <cmath>
#include <cstring>
#include <functional>
#include <future>
#include <span>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

namespace hex::plugin::builtin {

    using namespace wolv::literals;

    namespace {

        constexpr size_t ScanChunkSize    = 1_MiB;
        constexpr size_t MaxSearchResults = 10000;
        constexpr size_t MaxStringResults = 100000;
        constexpr size_t MaxEntropyBlocks = 8192;

        /**
         * @brief Gets the currently selected provider or throws if there is none
         */
        prv::Provider* getSelectedProvider() {
            auto *provider = ImHexApi::Provider::get();
            if (provider == nullptr)
                throw std::runtime_error("No data source is currently open. Use the open_file tool first.");

            return provider;
        }

        /**
         * @brief Gets the currently selected provider or throws if there is none or it cannot be read from yet
         */
        prv::Provider* getActiveProvider() {
            auto *provider = getSelectedProvider();
            if (!provider->isReadable())
                throw std::runtime_error("The current data source is not readable. If it was just opened, the open may still be in progress or may have failed.");

            return provider;
        }

        /**
         * @brief Finds a provider by its handle or returns nullptr
         */
        prv::Provider* findProviderByHandle(u64 handle) {
            for (auto *provider : ImHexApi::Provider::getProviders()) {
                if (provider->getID() == handle)
                    return provider;
            }

            return nullptr;
        }

        /**
         * @brief Validates an address against the provider size and clamps the requested size to the available range
         */
        u64 clampRegion(prv::Provider *provider, u64 address, u64 requestedSize) {
            const u64 providerSize = provider->getActualSize();
            if (address >= providerSize)
                throw std::runtime_error(fmt::format("Address 0x{:X} is out of range, the data source is 0x{:X} bytes large", address, providerSize));

            return std::min(requestedSize, providerSize - address);
        }

        /**
         * @brief Executes a function on the main thread and returns its result.
         *
         * Tools that mutate GUI-owned state (providers list, bookmarks) must not touch it from
         * the MCP server thread. The GUI main loop and the headless MCP server loop both pump
         * TaskManager::runDeferredCalls(), so deferred calls execute within a frame.
         */
        nlohmann::json runOnMainThread(std::function<nlohmann::json()> function) {
            auto promise = std::make_shared<std::promise<nlohmann::json>>();
            auto future = promise->get_future();

            TaskManager::doLater([promise, function = std::move(function)] {
                try {
                    promise->set_value(function());
                } catch (...) {
                    promise->set_exception(std::current_exception());
                }
            });

            if (future.wait_for(std::chrono::seconds(10)) != std::future_status::ready)
                throw std::runtime_error("Timed out waiting for the main thread to process the request");

            return future.get();
        }

        nlohmann::json makeResult(const nlohmann::json &result) {
            return mcp::StructuredContent {
                .text = result.dump(),
                .data = result
            };
        }

        /**
         * @brief Decodes a tool payload string with the given encoding into raw bytes
         */
        std::vector<u8> decodePayload(const std::string &payload, const std::string &encoding) {
            if (encoding == "hex") {
                auto bytes = hex::parseHexString(payload);
                if (bytes.empty())
                    throw std::runtime_error("Invalid hex string. Expected an even number of hex digits, e.g. 'DEADBEEF' or 'DE AD BE EF'");

                return bytes;
            } else if (encoding == "base64") {
                auto bytes = crypt::decode64({ payload.begin(), payload.end() });
                if (bytes.empty())
                    throw std::runtime_error("Invalid base64 string");

                return bytes;
            } else if (encoding == "ascii") {
                if (payload.empty())
                    throw std::runtime_error("Payload must not be empty");

                return { payload.begin(), payload.end() };
            }

            throw std::runtime_error(fmt::format("Unknown encoding '{}'. Supported encodings are 'hex', 'base64' and 'ascii'", encoding));
        }

        std::string encodeBase64(std::span<const u8> data) {
            auto encoded = crypt::encode64({ data.begin(), data.end() });

            return { encoded.begin(), encoded.end() };
        }

        /**
         * @brief Searches for a byte pattern in the given range using chunked reads.
         *
         * Chunks overlap by patternSize - 1 bytes so matches spanning chunk boundaries are found.
         */
        std::vector<u64> searchPattern(prv::Provider *provider, std::span<const u8> pattern, u64 startAddress, u64 endAddress, size_t maxResults, bool &truncated) {
            std::vector<u64> results;
            truncated = false;

            const size_t patternSize = pattern.size();
            if (patternSize == 0 || startAddress >= endAddress || endAddress - startAddress < patternSize)
                return results;

            const auto searcher = std::boyer_moore_horspool_searcher(pattern.begin(), pattern.end());

            std::vector<u8> buffer;
            u64 offset = startAddress;
            while (offset + patternSize <= endAddress) {
                const size_t readSize = std::min<u64>(ScanChunkSize, endAddress - offset);
                if (readSize < patternSize)
                    break;

                buffer.resize(readSize);
                provider->read(offset, buffer.data(), readSize);

                auto it = buffer.begin();
                const auto bufferEnd = buffer.end();
                while (true) {
                    it = std::search(it, bufferEnd, searcher);
                    if (it == bufferEnd)
                        break;

                    results.push_back(offset + std::distance(buffer.begin(), it));
                    if (results.size() >= maxResults) {
                        truncated = true;
                        return results;
                    }

                    ++it;
                }

                offset += readSize - patternSize + 1;
            }

            return results;
        }

        std::vector<u8> parseSearchPattern(const std::string &pattern, const std::string &type) {
            if (type == "hex") {
                auto bytes = hex::parseHexString(pattern);
                if (bytes.empty())
                    throw std::runtime_error(fmt::format("Invalid hex search pattern '{}'", pattern));

                return bytes;
            } else if (type == "ascii") {
                if (pattern.empty())
                    throw std::runtime_error("Search pattern must not be empty");

                return { pattern.begin(), pattern.end() };
            }

            throw std::runtime_error(fmt::format("Unknown pattern type '{}'. Supported types are 'hex' and 'ascii'", type));
        }

        /**
         * @brief Calculates the Shannon entropy in bits per byte from a byte frequency table.
         *
         * Computed exactly instead of using the quantized lookup table of the legacy MCP plugin,
         * which produced out-of-bounds accesses for single-value blocks and up to ~17% error.
         */
        double entropyFromFrequencies(const std::array<u64, 256> &frequencies, u64 totalSize) {
            if (totalSize == 0)
                return 0.0;

            double entropy = 0.0;
            const auto total = double(totalSize);
            for (const auto count : frequencies) {
                if (count == 0)
                    continue;

                const double probability = double(count) / total;
                entropy -= probability * std::log2(probability);
            }

            return entropy;
        }

        /**
         * @brief Identifies a file type based on its magic bytes
         */
        std::string detectFileType(prv::Provider *provider, std::span<const u8> header) {
            struct MagicEntry {
                std::vector<u8> magic;
                const char *description;
            };

            // Sorted so longer, more specific signatures are matched first
            static const std::vector<MagicEntry> MagicTable = {
                { { 0x53, 0x51, 0x4C, 0x69, 0x74, 0x65, 0x20, 0x66, 0x6F, 0x72, 0x6D, 0x61, 0x74, 0x20, 0x33, 0x00 }, "SQLite 3 Database" },
                { { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A }, "PNG Image" },
                { { 0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1 }, "Microsoft Compound File (DOC/XLS/MSI)" },
                { { 0x52, 0x61, 0x72, 0x21, 0x1A, 0x07 }, "RAR Archive" },
                { { 0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C }, "7-Zip Archive" },
                { { 0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00 }, "XZ Compressed Data" },
                { { 0x7B, 0x5C, 0x72, 0x74, 0x66 }, "RTF Document" },
                { { 0x7F, 0x45, 0x4C, 0x46 }, "ELF Executable" },
                { { 0xCF, 0xFA, 0xED, 0xFE }, "Mach-O Executable (64-bit)" },
                { { 0xCE, 0xFA, 0xED, 0xFE }, "Mach-O Executable (32-bit)" },
                { { 0xFE, 0xED, 0xFA, 0xCF }, "Mach-O Executable (64-bit, Big Endian)" },
                { { 0xFE, 0xED, 0xFA, 0xCE }, "Mach-O Executable (32-bit, Big Endian)" },
                { { 0xCA, 0xFE, 0xBA, 0xBE }, "Mach-O Universal Binary / Java Class" },
                { { 0x64, 0x65, 0x78, 0x0A }, "Android DEX Bytecode" },
                { { 0x00, 0x61, 0x73, 0x6D }, "WebAssembly Binary" },
                { { 0x50, 0x4B, 0x03, 0x04 }, "ZIP Archive" },
                { { 0x50, 0x4B, 0x05, 0x06 }, "ZIP Archive (Empty)" },
                { { 0x50, 0x4B, 0x07, 0x08 }, "ZIP Archive (Spanned)" },
                { { 0x04, 0x22, 0x4D, 0x18 }, "LZ4 Frame" },
                { { 0x28, 0xB5, 0x2F, 0xFD }, "Zstandard Compressed Data" },
                { { 0x4D, 0x53, 0x43, 0x46 }, "Microsoft Cabinet Archive" },
                { { 0x47, 0x49, 0x46, 0x38 }, "GIF Image" },
                { { 0x4F, 0x67, 0x67, 0x53 }, "OGG Container" },
                { { 0x66, 0x4C, 0x61, 0x43 }, "FLAC Audio" },
                { { 0x4D, 0x54, 0x68, 0x64 }, "MIDI Audio" },
                { { 0x25, 0x50, 0x44, 0x46 }, "PDF Document" },
                { { 0x25, 0x21, 0x50, 0x53 }, "PostScript Document" },
                { { 0xD4, 0xC3, 0xB2, 0xA1 }, "PCAP Capture (Little Endian)" },
                { { 0xA1, 0xB2, 0xC3, 0xD4 }, "PCAP Capture (Big Endian)" },
                { { 0x0A, 0x0D, 0x0D, 0x0A }, "PCAPNG Capture" },
                { { 0x4E, 0x45, 0x53, 0x1A }, "NES ROM" },
                { { 0x1A, 0x45, 0xDF, 0xA3 }, "Matroska/WebM Container" },
                { { 0x30, 0x26, 0xB2, 0x75 }, "ASF/WMV Container" },
                { { 0xFF, 0xD8, 0xFF }, "JPEG Image" },
                { { 0x42, 0x5A, 0x68 }, "BZIP2 Compressed Data" },
                { { 0x49, 0x44, 0x33 }, "MP3 Audio (ID3)" },
                { { 0xEF, 0xBB, 0xBF }, "UTF-8 Text (with BOM)" },
                { { 0x1F, 0x8B }, "GZIP Compressed Data" },
                { { 0x4D, 0x5A }, "Windows PE/COFF Executable" },
                { { 0x42, 0x4D }, "BMP Image" },
                { { 0xFF, 0xFE }, "UTF-16 LE Text (with BOM)" },
                { { 0xFE, 0xFF }, "UTF-16 BE Text (with BOM)" },
            };

            for (const auto &[magic, description] : MagicTable) {
                if (header.size() >= magic.size() && std::memcmp(header.data(), magic.data(), magic.size()) == 0)
                    return description;
            }

            // Signatures that don't start at offset 0
            if (header.size() >= 12 && std::memcmp(header.data() + 4, "ftyp", 4) == 0)
                return "MP4/QuickTime Container";

            if (header.size() >= 12 && std::memcmp(header.data(), "RIFF", 4) == 0) {
                if (std::memcmp(header.data() + 8, "WAVE", 4) == 0) return "WAVE Audio";
                if (std::memcmp(header.data() + 8, "AVI ", 4) == 0) return "AVI Video";
                if (std::memcmp(header.data() + 8, "WEBP", 4) == 0) return "WebP Image";

                return "RIFF Container";
            }

            if (provider->getActualSize() >= 262 + 5) {
                std::array<u8, 5> tarMagic = {};
                provider->read(257, tarMagic.data(), tarMagic.size());
                if (std::memcmp(tarMagic.data(), "ustar", 5) == 0)
                    return "TAR Archive";
            }

            return "Unknown";
        }

        nlohmann::json bookmarkToJson(const ImHexApi::Bookmarks::Entry &entry) {
            return {
                { "id", entry.id },
                { "address", entry.region.address },
                { "size", entry.region.size },
                { "name", entry.name },
                { "comment", entry.comment },
                { "color", entry.color }
            };
        }

    }

    void registerMCPTools() {
        ContentRegistry::MCP::registerTool(romfs::get("mcp/tools/open_file.json").string(), [](const nlohmann::json &data) -> nlohmann::json {
            auto filePath = data.at("file_path").get<std::string>();

            auto provider = ImHexApi::Provider::createProvider("hex.builtin.provider.file", true);
            if (auto *fileProvider = dynamic_cast<FileProvider*>(provider.get()); fileProvider != nullptr) {
                fileProvider->setPath(filePath);

                ImHexApi::Provider::openProvider(provider);
            }

            // The actual open happens asynchronously on a task thread. Wait for it to either
            // succeed (provider becomes readable) or fail (provider gets removed again) so
            // the returned metadata is accurate and follow-up reads can't race the open.
            const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(30);
            while (!provider->isReadable()) {
                if (findProviderByHandle(provider->getID()) == nullptr)
                    throw std::runtime_error(fmt::format("Failed to open file '{}'", filePath));

                if (std::chrono::steady_clock::now() > deadline)
                    throw std::runtime_error(fmt::format("Timed out waiting for file '{}' to open", filePath));

                std::this_thread::sleep_for(std::chrono::milliseconds(50));
            }

            nlohmann::json result = {
                { "handle", provider->getID() },
                { "name", provider->getName() },
                { "type", provider->getTypeName().get() },
                { "size", provider->getSize() },
                { "is_writable", provider->isWritable() }
            };

            return makeResult(result);
        });

        ContentRegistry::MCP::registerTool(romfs::get("mcp/tools/list_open_data_sources.json").string(), [](const nlohmann::json &) -> nlohmann::json {
            const auto &providers = ImHexApi::Provider::getProviders();
            nlohmann::json array = nlohmann::json::array();
            for (const auto &provider : providers) {
                nlohmann::json providerInfo;
                providerInfo["name"] = provider->getName();
                providerInfo["type"] = provider->getTypeName().get();
                providerInfo["size"] = provider->getSize();
                providerInfo["is_writable"] = provider->isWritable();
                providerInfo["handle"] = provider->getID();

                array.push_back(providerInfo);
            }

            nlohmann::json result;
            result["data_sources"] = array;

            return makeResult(result);
        });

        ContentRegistry::MCP::registerTool(romfs::get("mcp/tools/select_data_source.json").string(), [](const nlohmann::json &data) -> nlohmann::json {
            const auto &providers = ImHexApi::Provider::getProviders();
            auto handle = data.at("handle").get<u64>();

            for (size_t i = 0; i < providers.size(); i++) {
                if (providers[i]->getID() == handle) {
                    ImHexApi::Provider::setCurrentProvider(static_cast<i64>(i));
                    break;
                }
            }

            nlohmann::json result = {
                { "selected_handle", getSelectedProvider()->getID() }
            };
            return makeResult(result);
        });

        ContentRegistry::MCP::registerTool(romfs::get("mcp/tools/read_data.json").string(), [](const nlohmann::json &data) -> nlohmann::json {
            auto address = data.at("address").get<u64>();
            auto size = data.at("size").get<u64>();

            size = std::min<u64>(size, 16_MiB);

            auto provider = getActiveProvider();
            size = clampRegion(provider, address, size);

            std::vector<u8> buffer(size);
            provider->read(address, buffer.data(), buffer.size());

            nlohmann::json result = {
                { "handle", provider->getID() },
                { "data", encodeBase64(buffer) },
                { "data_size", buffer.size() }
            };
            return makeResult(result);
        });

        ContentRegistry::MCP::registerTool(romfs::get("mcp/tools/write_data.json").string(), [](const nlohmann::json &data) -> nlohmann::json {
            auto address = data.at("address").get<u64>();
            auto payload = data.at("data").get<std::string>();
            auto encoding = data.value("encoding", "hex");

            auto bytes = decodePayload(payload, encoding);

            return runOnMainThread([address, bytes = std::move(bytes)] {
                auto provider = getActiveProvider();

                if (!provider->isWritable())
                    throw std::runtime_error("The current data source is read-only");

                if (address + bytes.size() > provider->getActualSize())
                    throw std::runtime_error(fmt::format("Write of 0x{:X} bytes at address 0x{:X} would exceed the data source size of 0x{:X} bytes", bytes.size(), address, provider->getActualSize()));

                provider->write(address, bytes.data(), bytes.size());

                nlohmann::json result = {
                    { "handle", provider->getID() },
                    { "address", address },
                    { "bytes_written", bytes.size() }
                };
                return makeResult(result);
            });
        });

        ContentRegistry::MCP::registerTool(romfs::get("mcp/tools/read_chunked.json").string(), [](const nlohmann::json &data) -> nlohmann::json {
            auto provider = getActiveProvider();

            const auto address = data.value("address", u64(0));
            const auto chunkIndex = data.value("chunk_index", u64(0));
            const auto encoding = data.value("encoding", "base64");
            auto chunkSize = std::clamp<u64>(data.value("chunk_size", u64(1_MiB)), 4_kiB, 16_MiB);

            u64 totalSize = data.contains("size") ? data.at("size").get<u64>() : provider->getActualSize() - std::min(address, provider->getActualSize());
            totalSize = clampRegion(provider, address, totalSize);

            const u64 totalChunks = (totalSize + chunkSize - 1) / chunkSize;
            if (chunkIndex >= totalChunks)
                throw std::runtime_error(fmt::format("Chunk index {} is out of range, the requested region only has {} chunks", chunkIndex, totalChunks));

            const u64 chunkAddress = address + chunkIndex * chunkSize;
            const u64 readSize = std::min<u64>(chunkSize, (address + totalSize) - chunkAddress);

            std::vector<u8> buffer(readSize);
            provider->read(chunkAddress, buffer.data(), buffer.size());

            std::string encodedData;
            if (encoding == "hex")
                encodedData = crypt::encode16(buffer);
            else if (encoding == "base64")
                encodedData = encodeBase64(buffer);
            else
                throw std::runtime_error(fmt::format("Unknown encoding '{}'. Supported encodings are 'hex' and 'base64'", encoding));

            nlohmann::json result = {
                { "handle", provider->getID() },
                { "data", encodedData },
                { "encoding", encoding },
                { "chunk_address", chunkAddress },
                { "chunk_index", chunkIndex },
                { "chunk_data_size", readSize },
                { "total_chunks", totalChunks },
                { "has_more", chunkIndex + 1 < totalChunks }
            };
            return makeResult(result);
        });

        ContentRegistry::MCP::registerTool(romfs::get("mcp/tools/search_bytes.json").string(), [](const nlohmann::json &data) -> nlohmann::json {
            auto provider = getActiveProvider();

            const auto pattern = data.at("pattern").get<std::string>();
            const auto type = data.value("type", "hex");
            const auto startAddress = data.value("start_address", u64(0));
            const auto endAddress = std::min<u64>(data.value("end_address", provider->getActualSize()), provider->getActualSize());
            const auto maxResults = std::clamp<u64>(data.value("max_results", u64(1000)), 1, MaxSearchResults);

            const auto patternBytes = parseSearchPattern(pattern, type);

            bool truncated = false;
            const auto matches = searchPattern(provider, patternBytes, startAddress, endAddress, maxResults, truncated);

            nlohmann::json result = {
                { "handle", provider->getID() },
                { "matches", matches },
                { "count", matches.size() },
                { "truncated", truncated }
            };
            return makeResult(result);
        });

        ContentRegistry::MCP::registerTool(romfs::get("mcp/tools/search_multiple.json").string(), [](const nlohmann::json &data) -> nlohmann::json {
            auto provider = getActiveProvider();

            const auto &patterns = data.at("patterns");
            if (!patterns.is_array() || patterns.empty())
                throw std::runtime_error("'patterns' must be a non-empty array");
            if (patterns.size() > 20)
                throw std::runtime_error("A maximum of 20 patterns can be searched at once");

            const auto maxResults = std::clamp<u64>(data.value("max_results_per_pattern", u64(1000)), 1, MaxSearchResults);

            nlohmann::json results = nlohmann::json::array();
            for (const auto &patternObject : patterns) {
                const auto pattern = patternObject.at("pattern").get<std::string>();
                const auto type = patternObject.value("type", "hex");

                const auto patternBytes = parseSearchPattern(pattern, type);

                bool truncated = false;
                const auto matches = searchPattern(provider, patternBytes, 0, provider->getActualSize(), maxResults, truncated);

                results.push_back({
                    { "pattern", pattern },
                    { "type", type },
                    { "matches", matches },
                    { "count", matches.size() },
                    { "truncated", truncated }
                });
            }

            nlohmann::json result = {
                { "handle", provider->getID() },
                { "results", results }
            };
            return makeResult(result);
        });

        ContentRegistry::MCP::registerTool(romfs::get("mcp/tools/extract_strings.json").string(), [](const nlohmann::json &data) -> nlohmann::json {
            auto provider = getActiveProvider();

            const auto minLength = std::clamp<u64>(data.value("min_length", u64(4)), 1, 256);
            const auto maxStringLength = std::clamp<u64>(data.value("max_string_length", u64(256)), minLength, 4096);
            const auto encoding = data.value("encoding", "ascii");
            const auto startAddress = data.value("start_address", u64(0));
            const auto endAddress = std::min<u64>(data.value("end_address", provider->getActualSize()), provider->getActualSize());
            const auto maxStrings = std::clamp<u64>(data.value("max_strings", u64(10000)), 1, MaxStringResults);

            if (encoding != "ascii" && encoding != "utf16le")
                throw std::runtime_error(fmt::format("Unknown encoding '{}'. Supported encodings are 'ascii' and 'utf16le'", encoding));

            const bool utf16 = encoding == "utf16le";

            nlohmann::json strings = nlohmann::json::array();
            bool truncated = false;

            std::string currentString;
            u64 stringStartAddress = 0;
            bool expectNullByte = false;

            const auto isPrintable = [](u8 byte) {
                return byte >= 0x20 && byte <= 0x7E;
            };

            const auto flush = [&] {
                if (currentString.size() >= minLength && strings.size() < maxStrings) {
                    strings.push_back({
                        { "address", stringStartAddress },
                        { "value", currentString },
                        { "length", currentString.size() }
                    });
                }

                currentString.clear();
                expectNullByte = false;
            };

            std::vector<u8> buffer;
            for (u64 offset = startAddress; offset < endAddress && !truncated; offset += buffer.size()) {
                buffer.resize(std::min<u64>(ScanChunkSize, endAddress - offset));
                provider->read(offset, buffer.data(), buffer.size());

                for (size_t i = 0; i < buffer.size(); i += 1) {
                    const u8 byte = buffer[i];
                    const u64 byteAddress = offset + i;

                    if (utf16 && expectNullByte) {
                        if (byte == 0x00) {
                            expectNullByte = false;
                        } else {
                            // The previous printable byte was not part of a UTF-16 string, drop it
                            currentString.pop_back();
                            flush();

                            if (isPrintable(byte)) {
                                stringStartAddress = byteAddress;
                                currentString.push_back(char(byte));
                                expectNullByte = true;
                            }
                        }
                    } else if (isPrintable(byte)) {
                        if (currentString.empty())
                            stringStartAddress = byteAddress;

                        currentString.push_back(char(byte));
                        expectNullByte = utf16;
                    } else {
                        flush();
                    }

                    if (currentString.size() >= maxStringLength && !expectNullByte)
                        flush();

                    if (strings.size() >= maxStrings) {
                        truncated = true;
                        break;
                    }
                }
            }

            if (!truncated) {
                // Drop a trailing UTF-16 character whose null byte was never confirmed
                if (expectNullByte && !currentString.empty())
                    currentString.pop_back();

                flush();
            }

            nlohmann::json result = {
                { "handle", provider->getID() },
                { "encoding", encoding },
                { "strings", strings },
                { "count", strings.size() },
                { "truncated", truncated }
            };
            return makeResult(result);
        });

        ContentRegistry::MCP::registerTool(romfs::get("mcp/tools/calculate_hash.json").string(), [](const nlohmann::json &data) -> nlohmann::json {
            auto provider = getActiveProvider();

            const auto algorithm = data.value("algorithm", "sha256");
            const auto address = data.value("address", u64(0));
            u64 size = data.contains("size") ? data.at("size").get<u64>() : provider->getActualSize() - std::min(address, provider->getActualSize());
            size = clampRegion(provider, address, size);

            const auto toHex = [](const auto &hashArray) {
                return crypt::encode16({ hashArray.begin(), hashArray.end() });
            };

            std::string hash;
            if (algorithm == "crc32")
                hash = fmt::format("{:08X}", crypt::crc32(provider, address, size, 0x04C11DB7, 0xFFFFFFFF, 0xFFFFFFFF, true, true));
            else if (algorithm == "md5")
                hash = toHex(crypt::md5(provider, address, size));
            else if (algorithm == "sha1")
                hash = toHex(crypt::sha1(provider, address, size));
            else if (algorithm == "sha224")
                hash = toHex(crypt::sha224(provider, address, size));
            else if (algorithm == "sha256")
                hash = toHex(crypt::sha256(provider, address, size));
            else if (algorithm == "sha384")
                hash = toHex(crypt::sha384(provider, address, size));
            else if (algorithm == "sha512")
                hash = toHex(crypt::sha512(provider, address, size));
            else
                throw std::runtime_error(fmt::format("Unknown algorithm '{}'. Supported algorithms are 'crc32', 'md5', 'sha1', 'sha224', 'sha256', 'sha384' and 'sha512'", algorithm));

            nlohmann::json result = {
                { "handle", provider->getID() },
                { "algorithm", algorithm },
                { "hash", hash },
                { "address", address },
                { "size", size }
            };
            return makeResult(result);
        });

        ContentRegistry::MCP::registerTool(romfs::get("mcp/tools/detect_file_type.json").string(), [](const nlohmann::json &) -> nlohmann::json {
            auto provider = getActiveProvider();

            std::vector<u8> header(std::min<u64>(provider->getActualSize(), 32));
            if (!header.empty())
                provider->read(0, header.data(), header.size());

            const auto magicPreviewSize = std::min<size_t>(header.size(), 16);

            nlohmann::json result = {
                { "handle", provider->getID() },
                { "file_type", detectFileType(provider, header) },
                { "magic_bytes", crypt::encode16({ header.begin(), header.begin() + magicPreviewSize }) },
                { "size", provider->getActualSize() }
            };
            return makeResult(result);
        });

        ContentRegistry::MCP::registerTool(romfs::get("mcp/tools/calculate_entropy.json").string(), [](const nlohmann::json &data) -> nlohmann::json {
            auto provider = getActiveProvider();

            const auto address = data.value("address", u64(0));
            u64 size = data.contains("size") ? data.at("size").get<u64>() : provider->getActualSize() - std::min(address, provider->getActualSize());
            size = clampRegion(provider, address, size);

            const auto blockSize = std::clamp<u64>(data.value("block_size", u64(256)), 16, 1_MiB);

            const u64 blockCount = (size + blockSize - 1) / blockSize;
            if (blockCount > MaxEntropyBlocks)
                throw std::runtime_error(fmt::format("The requested region would produce {} blocks but only {} are allowed. Increase block_size to at least 0x{:X} bytes", blockCount, MaxEntropyBlocks, (size + MaxEntropyBlocks - 1) / MaxEntropyBlocks));

            nlohmann::json blocks = nlohmann::json::array();
            std::array<u64, 256> totalFrequencies = {};

            std::vector<u8> buffer;
            for (u64 blockIndex = 0; blockIndex < blockCount; blockIndex += 1) {
                const u64 blockAddress = address + blockIndex * blockSize;
                const u64 readSize = std::min<u64>(blockSize, (address + size) - blockAddress);

                buffer.resize(readSize);
                provider->read(blockAddress, buffer.data(), buffer.size());

                std::array<u64, 256> frequencies = {};
                for (const u8 byte : buffer)
                    frequencies[byte] += 1;

                for (size_t i = 0; i < frequencies.size(); i += 1)
                    totalFrequencies[i] += frequencies[i];

                blocks.push_back({
                    { "address", blockAddress },
                    { "size", readSize },
                    { "entropy", entropyFromFrequencies(frequencies, readSize) }
                });
            }

            nlohmann::json result = {
                { "handle", provider->getID() },
                { "block_size", blockSize },
                { "overall_entropy", entropyFromFrequencies(totalFrequencies, size) },
                { "blocks", blocks },
                { "count", blocks.size() }
            };
            return makeResult(result);
        });

        ContentRegistry::MCP::registerTool(romfs::get("mcp/tools/get_byte_statistics.json").string(), [](const nlohmann::json &data) -> nlohmann::json {
            auto provider = getActiveProvider();

            const auto address = data.value("address", u64(0));
            u64 size = data.contains("size") ? data.at("size").get<u64>() : provider->getActualSize() - std::min(address, provider->getActualSize());
            size = clampRegion(provider, address, size);

            const bool includeDistribution = data.value("include_distribution", false);

            std::array<u64, 256> frequencies = {};
            std::vector<u8> buffer;
            for (u64 offset = address; offset < address + size; offset += buffer.size()) {
                buffer.resize(std::min<u64>(ScanChunkSize, (address + size) - offset));
                provider->read(offset, buffer.data(), buffer.size());

                for (const u8 byte : buffer)
                    frequencies[byte] += 1;
            }

            u64 uniqueBytes = 0;
            u64 printableBytes = 0;
            u8 mostCommonByte = 0;
            u64 mostCommonCount = 0;

            for (size_t i = 0; i < frequencies.size(); i += 1) {
                if (frequencies[i] > 0)
                    uniqueBytes += 1;
                if (i >= 0x20 && i <= 0x7E)
                    printableBytes += frequencies[i];
                if (frequencies[i] > mostCommonCount) {
                    mostCommonCount = frequencies[i];
                    mostCommonByte = u8(i);
                }
            }

            const u64 nullBytes = frequencies[0];

            nlohmann::json result = {
                { "handle", provider->getID() },
                { "address", address },
                { "size", size },
                { "unique_bytes", uniqueBytes },
                { "null_bytes", nullBytes },
                { "null_percentage", size > 0 ? (double(nullBytes) / double(size)) * 100.0 : 0.0 },
                { "printable_bytes", printableBytes },
                { "printable_percentage", size > 0 ? (double(printableBytes) / double(size)) * 100.0 : 0.0 },
                { "most_common_byte", mostCommonByte },
                { "most_common_count", mostCommonCount },
                { "entropy", entropyFromFrequencies(frequencies, size) }
            };

            if (includeDistribution)
                result["distribution"] = frequencies;

            return makeResult(result);
        });

        ContentRegistry::MCP::registerTool(romfs::get("mcp/tools/get_provider_info.json").string(), [](const nlohmann::json &data) -> nlohmann::json {
            prv::Provider *provider = nullptr;
            if (data.contains("handle")) {
                provider = findProviderByHandle(data.at("handle").get<u64>());
                if (provider == nullptr)
                    throw std::runtime_error(fmt::format("No data source with handle {} found", data.at("handle").get<u64>()));
            } else {
                provider = getSelectedProvider();
            }

            nlohmann::json result = {
                { "handle", provider->getID() },
                { "name", provider->getName() },
                { "type", provider->getTypeName().get() },
                { "size", provider->getSize() },
                { "is_readable", provider->isReadable() },
                { "is_writable", provider->isWritable() },
                { "is_dirty", provider->isDirty() }
            };
            return makeResult(result);
        });

        ContentRegistry::MCP::registerTool(romfs::get("mcp/tools/close_file.json").string(), [](const nlohmann::json &data) -> nlohmann::json {
            const auto handle = data.at("handle").get<u64>();

            return runOnMainThread([handle] {
                auto *provider = findProviderByHandle(handle);
                if (provider == nullptr)
                    throw std::runtime_error(fmt::format("No data source with handle {} found", handle));

                ImHexApi::Provider::remove(provider, true);

                // Provider::remove() refuses to remove while tasks are running, report whether it worked
                const bool closed = findProviderByHandle(handle) == nullptr;

                nlohmann::json result = {
                    { "handle", handle },
                    { "closed", closed }
                };

                if (!closed)
                    result["message"] = "The data source could not be closed because tasks are still running. Try again later.";

                return makeResult(result);
            });
        });

        ContentRegistry::MCP::registerTool(romfs::get("mcp/tools/add_bookmark.json").string(), [](const nlohmann::json &data) -> nlohmann::json {
            const auto address = data.at("address").get<u64>();
            const auto size = data.at("size").get<u64>();
            const auto name = data.value("name", "");
            const auto comment = data.value("comment", "");
            const auto color = data.value("color", u32(0));

            return runOnMainThread([address, size, name, comment, color] {
                getActiveProvider();

                const auto id = ImHexApi::Bookmarks::add(address, size, name, comment, color);

                nlohmann::json result = {
                    { "id", id },
                    { "address", address },
                    { "size", size }
                };
                return makeResult(result);
            });
        });

        ContentRegistry::MCP::registerTool(romfs::get("mcp/tools/remove_bookmark.json").string(), [](const nlohmann::json &data) -> nlohmann::json {
            const auto id = data.at("id").get<u64>();

            return runOnMainThread([id] {
                getActiveProvider();

                const auto entries = ImHexApi::Bookmarks::getEntries();
                const bool found = std::ranges::any_of(entries, [id](const auto &entry) { return entry.id == id; });
                if (!found)
                    throw std::runtime_error(fmt::format("No bookmark with ID {} found in the current data source", id));

                ImHexApi::Bookmarks::remove(id);

                nlohmann::json result = {
                    { "id", id },
                    { "removed", true }
                };
                return makeResult(result);
            });
        });

        ContentRegistry::MCP::registerTool(romfs::get("mcp/tools/list_bookmarks.json").string(), [](const nlohmann::json &) -> nlohmann::json {
            return runOnMainThread([] {
                auto provider = getActiveProvider();

                nlohmann::json bookmarks = nlohmann::json::array();
                for (const auto &entry : ImHexApi::Bookmarks::getEntries())
                    bookmarks.push_back(bookmarkToJson(entry));

                nlohmann::json result = {
                    { "handle", provider->getID() },
                    { "bookmarks", bookmarks },
                    { "count", bookmarks.size() }
                };
                return makeResult(result);
            });
        });
    }

}
