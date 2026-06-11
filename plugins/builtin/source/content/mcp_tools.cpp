#include <content/providers/file_provider.hpp>
#include <content/providers/memory_file_provider.hpp>
#include <content/providers/view_provider.hpp>
#include <hex/api/content_registry/communication_interface.hpp>
#include <hex/api/content_registry/data_formatter.hpp>
#include <hex/api/content_registry/hashes.hpp>
#include <hex/api/content_registry/pattern_language.hpp>
#include <hex/api/content_registry/reports.hpp>
#include <hex/api/content_registry/diffing.hpp>
#include <hex/api/imhex_api/provider.hpp>
#include <hex/api/imhex_api/bookmarks.hpp>
#include <hex/api/imhex_api/hex_editor.hpp>
#include <hex/api/task_manager.hpp>
#include <hex/helpers/crypto.hpp>
#include <hex/helpers/fmt.hpp>
#include <hex/helpers/magic.hpp>
#include <hex/helpers/utils.hpp>
#include <hex/providers/provider.hpp>
#include <hex/trace/stacktrace.hpp>
#include <romfs/romfs.hpp>
#include <wolv/literals.hpp>
#include <wolv/io/file.hpp>
#include <wolv/utils/string.hpp>

#include <nlohmann/json.hpp>

#include <pl/pattern_language.hpp>
#include <pl/formatters.hpp>
#include <pl/core/token.hpp>
#include <pl/core/errors/error.hpp>

#include <algorithm>
#include <array>
#include <bit>
#include <chrono>
#include <cmath>
#include <cstring>
#include <ctime>
#include <functional>
#include <future>
#include <map>
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

        // ============================================================================
        // PATTERN LANGUAGE HELPERS
        // ============================================================================

        /**
         * @brief Converts a pattern language literal (the type of in/out variables) to JSON
         */
        nlohmann::json literalToJson(const pl::core::Token::Literal &literal) {
            if (literal.isString())
                return literal.toString(false);
            if (literal.isBoolean())
                return literal.toBoolean();
            if (literal.isFloatingPoint())
                return literal.toFloatingPoint();
            if (literal.isCharacter())
                return std::string(1, literal.toCharacter());
            if (literal.isPattern())
                return literal.toString(true);
            if (literal.isSigned()) {
                auto value = literal.toSigned();
                if (value >= std::numeric_limits<i64>::min() && value <= std::numeric_limits<i64>::max())
                    return i64(value);
                return literal.toString(true);
            }
            if (literal.isUnsigned()) {
                auto value = literal.toUnsigned();
                if (value <= std::numeric_limits<u64>::max())
                    return u64(value);
                return literal.toString(true);
            }

            return literal.toString(true);
        }

        /**
         * @brief Converts a JSON value to a pattern language literal for use as an input variable
         */
        pl::core::Token::Literal jsonToLiteral(const nlohmann::json &value) {
            if (value.is_boolean())
                return value.get<bool>();
            if (value.is_number_unsigned())
                return u128(value.get<u64>());
            if (value.is_number_integer())
                return i128(value.get<i64>());
            if (value.is_number_float())
                return value.get<double>();
            if (value.is_string())
                return value.get<std::string>();

            throw std::runtime_error("Input variables must be numbers, booleans or strings");
        }

        nlohmann::json compileErrorToJson(const pl::core::err::CompileError &error) {
            const auto &location = error.getLocation();
            return {
                { "message", error.getMessage() },
                { "line", location.line },
                { "column", location.column }
            };
        }

        // ============================================================================
        // DATA INSPECTOR HELPERS (native, headless-safe — the registry display
        // functions call ImGui and cannot be used off the main thread)
        // ============================================================================

        template<typename T>
        T readScalar(std::span<const u8> data, std::endian endian) {
            std::array<u8, sizeof(T)> bytes = {};
            std::memcpy(bytes.data(), data.data(), sizeof(T));
            if (endian != std::endian::native)
                std::ranges::reverse(bytes);

            T value;
            std::memcpy(&value, bytes.data(), sizeof(T));
            return value;
        }

        i64 readSignedInteger(std::span<const u8> data, size_t byteCount, std::endian endian) {
            u64 raw = 0;
            for (size_t i = 0; i < byteCount; i++) {
                const size_t shift = endian == std::endian::little ? i : (byteCount - 1 - i);
                raw |= u64(data[i]) << (shift * 8);
            }
            // Sign-extend from byteCount*8 bits
            const u64 signBit = u64(1) << (byteCount * 8 - 1);
            if (raw & signBit)
                raw |= ~((signBit << 1) - 1);
            return i64(raw);
        }

        u64 readUnsignedInteger(std::span<const u8> data, size_t byteCount, std::endian endian) {
            u64 raw = 0;
            for (size_t i = 0; i < byteCount; i++) {
                const size_t shift = endian == std::endian::little ? i : (byteCount - 1 - i);
                raw |= u64(data[i]) << (shift * 8);
            }
            return raw;
        }

        std::string formatUnixTimestamp(i64 epochSeconds) {
            const std::time_t time = epochSeconds;
            std::tm tm = {};
        #if defined(_WIN32)
            if (gmtime_s(&tm, &time) != 0)
                return "invalid";
        #else
            if (gmtime_r(&time, &tm) == nullptr)
                return "invalid";
        #endif
            std::array<char, 32> buffer = {};
            if (std::strftime(buffer.data(), buffer.size(), "%Y-%m-%dT%H:%M:%SZ", &tm) == 0)
                return "invalid";
            return buffer.data();
        }

        /**
         * @brief Produces every common data-inspector interpretation of a byte window
         */
        nlohmann::json interpretBytes(std::span<const u8> data, std::endian endian) {
            nlohmann::json result = nlohmann::json::object();
            const size_t size = data.size();

            const auto addInt = [&](const char *name, size_t bytes, bool isSigned) {
                if (size < bytes) return;
                if (isSigned)
                    result[name] = readSignedInteger(data, bytes, endian);
                else
                    result[name] = readUnsignedInteger(data, bytes, endian);
            };

            addInt("u8", 1, false);   addInt("i8", 1, true);
            addInt("u16", 2, false);  addInt("i16", 2, true);
            addInt("u24", 3, false);  addInt("i24", 3, true);
            addInt("u32", 4, false);  addInt("i32", 4, true);
            addInt("u48", 6, false);  addInt("i48", 6, true);
            addInt("u64", 8, false);  addInt("i64", 8, true);

            if (size >= 4) result["f32"] = double(readScalar<float>(data, endian));
            if (size >= 8) result["f64"] = readScalar<double>(data, endian);

            if (size >= 1) {
                result["bool"] = data[0] != 0;
                const u8 c = data[0];
                result["char"] = (c >= 0x20 && c <= 0x7E) ? std::string(1, char(c)) : fmt::format("\\x{:02X}", c);
            }

            // Unsigned LEB128
            {
                u64 value = 0;
                size_t shift = 0, consumed = 0;
                bool ok = false;
                for (size_t i = 0; i < size && shift < 64; i++) {
                    value |= u64(data[i] & 0x7F) << shift;
                    consumed++;
                    if ((data[i] & 0x80) == 0) { ok = true; break; }
                    shift += 7;
                }
                if (ok) result["uleb128"] = { { "value", value }, { "byte_length", consumed } };
            }

            if (size >= 4)  result["time32"] = formatUnixTimestamp(i64(readScalar<u32>(data, endian)));
            if (size >= 8)  result["time64"] = formatUnixTimestamp(readSignedInteger(data, 8, endian));

            if (size >= 16) {
                // RFC 4122 (big-endian) UUID and Microsoft mixed-endian GUID
                const auto hex = [&](size_t off, size_t n) { return crypt::encode16({ data.begin() + off, data.begin() + off + n }); };
                result["uuid"] = fmt::format("{}-{}-{}-{}-{}", hex(0,4), hex(4,2), hex(6,2), hex(8,2), hex(10,6));
                result["guid"] = fmt::format("{:02X}{:02X}{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{}-{}",
                                             data[3], data[2], data[1], data[0], data[5], data[4], data[7], data[6],
                                             hex(8,2), hex(10,6));
            }

            return result;
        }

        // ============================================================================
        // PATTERN EXECUTION (shared by run_pattern_file and auto_analyze)
        // ============================================================================

        /**
         * @brief Runs a pattern on the current provider's runtime and collects the result.
         * @note The caller MUST hold ContentRegistry::PatternLanguage::getRuntimeLock().
         */
        nlohmann::json executePattern(prv::Provider *provider, const std::string &source,
                                      const std::string &sourceName,
                                      const std::map<std::string, pl::core::Token::Literal> &inVariables,
                                      bool includePatterns) {
            auto &runtime = ContentRegistry::PatternLanguage::getRuntime();
            ContentRegistry::PatternLanguage::configureRuntime(runtime, provider);

            std::vector<std::string> consoleLines;
            runtime.setLogCallback([&consoleLines](pl::core::LogConsole::Level level, const std::string &message) {
                const char *prefix = "";
                switch (level) {
                    using enum pl::core::LogConsole::Level;
                    case Debug:   prefix = "[D] "; break;
                    case Info:    prefix = "[I] "; break;
                    case Warning: prefix = "[W] "; break;
                    case Error:   prefix = "[E] "; break;
                    default: break;
                }
                consoleLines.push_back(prefix + message);
            });

            std::ignore = runtime.executeString(source, sourceName, {}, inVariables, true);
            runtime.setLogCallback({});

            const auto &compileErrors = runtime.getCompileErrors();
            const auto &evalError     = runtime.getEvalError();
            const bool success = compileErrors.empty() && !evalError.has_value();

            nlohmann::json compileErrorsJson = nlohmann::json::array();
            for (const auto &error : compileErrors)
                compileErrorsJson.push_back(compileErrorToJson(error));

            nlohmann::json evalErrorJson = nullptr;
            if (evalError.has_value())
                evalErrorJson = { { "message", evalError->message }, { "line", evalError->line }, { "column", evalError->column } };

            nlohmann::json outVariables = nlohmann::json::object();
            for (const auto &[name, value] : runtime.getOutVariables())
                outVariables[name] = literalToJson(value);

            nlohmann::json result = {
                { "success", success },
                { "pattern_count", runtime.getCreatedPatternCount() },
                { "compile_errors", compileErrorsJson },
                { "eval_error", evalErrorJson },
                { "out_variables", outVariables },
                { "console", wolv::util::combineStrings(consoleLines, "\n") }
            };

            if (includePatterns && success) {
                pl::gen::fmt::FormatterJson formatter;
                auto formatted = formatter.format(runtime);
                try {
                    result["patterns"] = nlohmann::json::parse(std::string(formatted.begin(), formatted.end()));
                } catch (const nlohmann::json::exception &) {
                    result["patterns"] = nlohmann::json::array();
                }
            }

            return result;
        }

        // ============================================================================
        // DIFFING HELPERS
        // ============================================================================

        const char* differenceTypeName(ContentRegistry::Diffing::DifferenceType type) {
            using enum ContentRegistry::Diffing::DifferenceType;
            switch (type) {
                case Match:     return "match";
                case Insertion: return "insertion";
                case Deletion:  return "deletion";
                case Mismatch:  return "mismatch";
            }
            return "unknown";
        }

        /**
         * @brief Serializes a diff interval tree into a JSON array of {start,end,size,type} regions,
         *        skipping plain matches (only differences are reported).
         */
        nlohmann::json diffTreeToJson(const ContentRegistry::Diffing::DiffTree &tree, size_t maxRegions, bool &truncated) {
            nlohmann::json regions = nlohmann::json::array();
            for (const auto &[start, data] : tree) {
                const auto end = data.first;
                const auto type = data.second;
                if (type == ContentRegistry::Diffing::DifferenceType::Match)
                    continue;

                if (regions.size() >= maxRegions) {
                    truncated = true;
                    break;
                }

                regions.push_back({
                    { "start", start },
                    { "end", end },
                    { "size", (end >= start) ? (end - start + 1) : 0 },
                    { "type", differenceTypeName(type) }
                });
            }
            return regions;
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

        // ====================================================================
        // PHASE 1 — ImHex core analysis surface
        // ====================================================================

        ContentRegistry::MCP::registerTool(romfs::get("mcp/tools/identify_file.json").string(), [](const nlohmann::json &) -> nlohmann::json {
            auto provider = getActiveProvider();

            // Real libmagic identification (much stronger than the signature table)
            auto description = magic::getDescription(provider);
            auto mimeType    = magic::getMIMEType(provider);
            auto extensions  = magic::getExtensions(provider);

            std::vector<u8> header(std::min<u64>(provider->getActualSize(), 32));
            if (!header.empty())
                provider->read(0, header.data(), header.size());
            const auto magicPreviewSize = std::min<size_t>(header.size(), 16);

            nlohmann::json result = {
                { "handle", provider->getID() },
                { "description", description },
                { "mime_type", mimeType },
                { "extensions", extensions },
                { "signature_match", detectFileType(provider, header) },
                { "magic_bytes", crypt::encode16({ header.begin(), header.begin() + magicPreviewSize }) },
                { "size", provider->getActualSize() }
            };
            return makeResult(result);
        });

        ContentRegistry::MCP::registerTool(romfs::get("mcp/tools/suggest_patterns.json").string(), [](const nlohmann::json &) -> nlohmann::json {
            auto provider = getActiveProvider();

            nlohmann::json patterns = nlohmann::json::array();
            for (const auto &found : magic::findViablePatterns(provider)) {
                nlohmann::json entry = {
                    { "path", wolv::util::toUTF8String(found.patternFilePath) },
                    { "author", found.author },
                    { "description", found.description }
                };
                if (found.mimeType.has_value())   entry["mime_type"] = *found.mimeType;
                if (found.magicOffset.has_value()) entry["magic_offset"] = *found.magicOffset;
                patterns.push_back(entry);
            }

            nlohmann::json result = {
                { "handle", provider->getID() },
                { "patterns", patterns },
                { "count", patterns.size() }
            };
            return makeResult(result);
        });

        ContentRegistry::MCP::registerTool(romfs::get("mcp/tools/run_pattern_file.json").string(), [](const nlohmann::json &data) -> nlohmann::json {
            auto provider = getActiveProvider();

            const bool hasSource = data.contains("source");
            const bool hasPath   = data.contains("path");
            if (hasSource == hasPath)
                throw std::runtime_error("Provide exactly one of 'source' (inline pattern code) or 'path' (a .hexpat file path)");

            std::string source;
            std::string sourceName = "mcp";
            if (hasSource) {
                source = data.at("source").get<std::string>();
            } else {
                auto path = data.at("path").get<std::string>();
                wolv::io::File file(std::fs::path(path), wolv::io::File::Mode::Read);
                if (!file.isValid())
                    throw std::runtime_error(fmt::format("Could not open pattern file '{}'", path));
                source = file.readString();
                sourceName = path;
            }

            std::map<std::string, pl::core::Token::Literal> inVariables;
            if (data.contains("in_variables")) {
                const auto &vars = data.at("in_variables");
                if (!vars.is_object())
                    throw std::runtime_error("'in_variables' must be an object");
                for (const auto &[name, value] : vars.items())
                    inVariables[name] = jsonToLiteral(value);
            }

            const bool includePatterns = data.value("include_patterns", true);

            auto lock = std::scoped_lock(ContentRegistry::PatternLanguage::getRuntimeLock());
            nlohmann::json result = executePattern(provider, source, sourceName, inVariables, includePatterns);
            result["handle"] = provider->getID();

            return makeResult(result);
        });

        ContentRegistry::MCP::registerTool(romfs::get("mcp/tools/inspect_data.json").string(), [](const nlohmann::json &data) -> nlohmann::json {
            auto provider = getActiveProvider();

            const auto address = data.at("address").get<u64>();
            const auto endianStr = data.value("endian", "little");
            if (endianStr != "little" && endianStr != "big")
                throw std::runtime_error("'endian' must be 'little' or 'big'");
            const auto endian = endianStr == "little" ? std::endian::little : std::endian::big;

            const u64 available = clampRegion(provider, address, 16);
            std::vector<u8> buffer(available);
            provider->read(address, buffer.data(), buffer.size());

            nlohmann::json interpretations = interpretBytes(buffer, endian);

            // Optional filter to a subset of interpretation names
            if (data.contains("types")) {
                const auto wanted = data.at("types").get<std::vector<std::string>>();
                nlohmann::json filtered = nlohmann::json::object();
                for (const auto &name : wanted) {
                    if (interpretations.contains(name))
                        filtered[name] = interpretations[name];
                }
                interpretations = filtered;
            }

            nlohmann::json result = {
                { "handle", provider->getID() },
                { "address", address },
                { "endian", endianStr },
                { "bytes_read", available },
                { "interpretations", interpretations }
            };
            return makeResult(result);
        });

        // ====================================================================
        // PHASE 2 — end-to-end workflows
        // ====================================================================

        ContentRegistry::MCP::registerTool(romfs::get("mcp/tools/auto_analyze.json").string(), [](const nlohmann::json &data) -> nlohmann::json {
            auto provider = getActiveProvider();

            // 1. Identify
            nlohmann::json identification = {
                { "description", magic::getDescription(provider) },
                { "mime_type", magic::getMIMEType(provider) },
                { "signature_match", [&] {
                    std::vector<u8> header(std::min<u64>(provider->getActualSize(), 32));
                    if (!header.empty()) provider->read(0, header.data(), header.size());
                    return detectFileType(provider, header);
                }() }
            };

            // 2. Suggest matching pattern files
            const auto viablePatterns = magic::findViablePatterns(provider);
            nlohmann::json suggested = nlohmann::json::array();
            for (const auto &found : viablePatterns)
                suggested.push_back({
                    { "path", wolv::util::toUTF8String(found.patternFilePath) },
                    { "description", found.description }
                });

            nlohmann::json result = {
                { "handle", provider->getID() },
                { "size", provider->getActualSize() },
                { "identification", identification },
                { "suggested_patterns", suggested },
                { "suggested_count", suggested.size() }
            };

            // 3. Run the best matching pattern, if any
            const bool includePatterns = data.value("include_patterns", true);
            if (!viablePatterns.empty()) {
                const auto &best = viablePatterns.front();
                wolv::io::File file(best.patternFilePath, wolv::io::File::Mode::Read);
                if (file.isValid()) {
                    auto source = file.readString();
                    auto sourceName = wolv::util::toUTF8String(best.patternFilePath);

                    auto lock = std::scoped_lock(ContentRegistry::PatternLanguage::getRuntimeLock());
                    auto applied = executePattern(provider, source, sourceName, {}, includePatterns);
                    applied["path"] = sourceName;
                    result["applied_pattern"] = applied;
                }
            }

            return makeResult(result);
        });

        ContentRegistry::MCP::registerTool(romfs::get("mcp/tools/open_memory.json").string(), [](const nlohmann::json &data) -> nlohmann::json {
            auto payload = data.at("data").get<std::string>();
            auto encoding = data.value("encoding", "hex");
            auto readOnly = data.value("read_only", false);

            auto bytes = decodePayload(payload, encoding);

            return runOnMainThread([bytes = std::move(bytes), readOnly] {
                auto provider = ImHexApi::Provider::createProvider("hex.builtin.provider.mem_file", true, true);
                if (provider == nullptr)
                    throw std::runtime_error("Failed to create an in-memory data source");

                if (auto *memProvider = dynamic_cast<MemoryFileProvider*>(provider.get()); memProvider != nullptr)
                    memProvider->setReadOnly(readOnly);

                provider->resize(bytes.size());
                provider->writeRaw(0, bytes.data(), bytes.size());
                provider->markDirty(false);

                nlohmann::json result = {
                    { "handle", provider->getID() },
                    { "name", provider->getName() },
                    { "type", provider->getTypeName().get() },
                    { "size", provider->getActualSize() },
                    { "is_writable", provider->isWritable() }
                };
                return makeResult(result);
            });
        });

        ContentRegistry::MCP::registerTool(romfs::get("mcp/tools/diff_data_sources.json").string(), [](const nlohmann::json &data) -> nlohmann::json {
            const auto handleA = data.at("handle_a").get<u64>();
            const auto handleB = data.at("handle_b").get<u64>();
            const auto algorithmName = data.value("algorithm", "");
            const auto maxRegions = std::clamp<u64>(data.value("max_regions", u64(1000)), 1, 100000);

            auto *providerA = findProviderByHandle(handleA);
            auto *providerB = findProviderByHandle(handleB);
            if (providerA == nullptr) throw std::runtime_error(fmt::format("No data source with handle {}", handleA));
            if (providerB == nullptr) throw std::runtime_error(fmt::format("No data source with handle {}", handleB));

            const auto &algorithms = ContentRegistry::Diffing::impl::getAlgorithms();
            if (algorithms.empty())
                throw std::runtime_error("No diffing algorithms are registered");

            // Pick the requested algorithm (by unlocalized-name substring), else the first (Simple)
            const ContentRegistry::Diffing::Algorithm *algorithm = algorithms.front().get();
            if (!algorithmName.empty()) {
                for (const auto &candidate : algorithms) {
                    if (std::string(candidate->getUnlocalizedName().get()).contains(algorithmName)) {
                        algorithm = candidate.get();
                        break;
                    }
                }
            }

            // The algorithms call TaskManager::getCurrentTask(), so they MUST run inside a task.
            auto promise = std::make_shared<std::promise<std::vector<ContentRegistry::Diffing::DiffTree>>>();
            auto future = promise->get_future();

            TaskManager::createTask("hex.builtin.mcp.diffing", TaskManager::NoProgress, [=](Task &) {
                try {
                    promise->set_value(algorithm->analyze(providerA, providerB));
                } catch (...) {
                    promise->set_exception(std::current_exception());
                }
            });

            if (future.wait_for(std::chrono::seconds(120)) != std::future_status::ready)
                throw std::runtime_error("Diffing timed out");

            auto trees = future.get();

            bool truncatedA = false, truncatedB = false;
            nlohmann::json result = {
                { "handle_a", handleA },
                { "handle_b", handleB },
                { "algorithm", algorithm->getUnlocalizedName().get() },
                { "size_a", providerA->getActualSize() },
                { "size_b", providerB->getActualSize() }
            };

            if (trees.size() >= 1) result["differences_a"] = diffTreeToJson(trees[0], maxRegions, truncatedA);
            if (trees.size() >= 2) result["differences_b"] = diffTreeToJson(trees[1], maxRegions, truncatedB);
            result["difference_count"] = result.value("differences_a", nlohmann::json::array()).size();
            result["truncated"] = truncatedA || truncatedB;

            return makeResult(result);
        });

        // -----------------------------------------------------------------
        // Phase 3 tools (breadth & ergonomics + first 3 from Phase 4)
        // -----------------------------------------------------------------

        // 1) calculate_hash (extended) - registry-backed, 30+ algorithms
        //    Replaces the prior hard-coded switch with a ContentRegistry::Hashes lookup.
        //    The agent passes any of the algorithm ids from list_hash_algorithms.
        //    The bridge proxy keeps the same name 'calculate_hash' for back-compat.
        ContentRegistry::MCP::registerTool(romfs::get("mcp/tools/calculate_hash.json").string(), [](const nlohmann::json &data) -> nlohmann::json {
            auto provider = getActiveProvider();

            const auto requested = data.value("algorithm", "sha256");
            // Normalize: lowercase, spaces to hyphens. "blake2b 256" -> "blake2b-256"
            auto normalize = [](std::string s) {
                for (char &c : s) if (c == ' ' || c == '\t') c = '-';
                for (char &c : s) c = static_cast<char>(std::tolower(c));
                return s;
            };
            const auto normalized = normalize(requested);

            const auto address = data.value("address", u64(0));
            u64 size = data.contains("size") ? data.at("size").get<u64>() : provider->getActualSize() - std::min(address, provider->getActualSize());
            size = clampRegion(provider, address, size);

            // Look up the hash in the ContentRegistry::Hashes registry. The LLM may pass
            // any of: (a) the full unlocalized name ("hex.hashes.hash.sha256"),
            // (b) the short form ("sha256"), (c) a normalized variant ("sha-256").
            // We match (a) directly, then (b) by comparing the substring after the
            // last '.' in the unlocalized name, then (c) by normalizing both.
            ContentRegistry::Hashes::Hash *selected = nullptr;
            std::string selectedName;
            for (auto &hash : ContentRegistry::Hashes::impl::getHashes()) {
                const auto unlocalized = std::string(hash->getUnlocalizedName().get());
                if (normalize(unlocalized) == normalized) { selected = hash.get(); selectedName = unlocalized; break; }
                const auto shortName = unlocalized.substr(unlocalized.rfind('.') + 1);
                if (shortName == requested || normalize(shortName) == normalized) {
                    selected = hash.get(); selectedName = unlocalized; break;
                }
            }
            if (selected == nullptr) {
                // Back-compat: if the hashes plugin is not loaded, the registry is
                // empty and only the legacy hard-coded algorithms are reachable. Fall
                // back to the crypt:: builtins. This keeps the old tool's behavior.
                std::string hash;
                const auto toHex = [](const auto &v) {
                    return crypt::encode16({ v.begin(), v.end() });
                };
                if (requested == "crc32")
                    hash = fmt::format("{:08X}", crypt::crc32(provider, address, size, 0x04C11DB7, 0xFFFFFFFF, 0xFFFFFFFF, true, true));
                else if (requested == "md5")  hash = toHex(crypt::md5(provider, address, size));
                else if (requested == "sha1") hash = toHex(crypt::sha1(provider, address, size));
                else if (requested == "sha224") hash = toHex(crypt::sha224(provider, address, size));
                else if (requested == "sha256") hash = toHex(crypt::sha256(provider, address, size));
                else if (requested == "sha384") hash = toHex(crypt::sha384(provider, address, size));
                else if (requested == "sha512") hash = toHex(crypt::sha512(provider, address, size));
                else
                    throw std::runtime_error(fmt::format("Unknown algorithm '{}'. Call list_hash_algorithms to see the supported ids.", requested));

                nlohmann::json result = {
                    { "handle",     provider->getID() },
                    { "algorithm",  requested },
                    { "hash",       hash },
                    { "address",    address },
                    { "size",       size }
                };
                return makeResult(result);
            }

            // Create the primary function: the unlocalized name (the hash plugin
            // registers a Function per named output, e.g. "hex.hashes.hash.sha256"
            // and "hex.hashes.hash.sha256.hex"). The primary function shares the
            // hash's own unlocalized name.
            auto function = selected->create(selectedName);
            const auto bytes = function.get({ address, size }, provider);
            const auto hex = crypt::encode16({ bytes.begin(), bytes.end() });

            nlohmann::json result = {
                { "handle",     provider->getID() },
                { "algorithm",  selectedName },
                { "hash",       hex },
                { "address",    address },
                { "size",       size }
            };
            return makeResult(result);
        });

        // 2) list_hash_algorithms - enumerate the Hashes registry. Pure read.
        //    Each algorithm's friendly id is the last component of the unlocalized
        //    name (e.g. "hex.hashes.hash.blake2b 256" -> "blake2b-256"). This is
        //    what the LLM should pass to calculate_hash.
        ContentRegistry::MCP::registerTool(romfs::get("mcp/tools/list_hash_algorithms.json").string(), [](const nlohmann::json &) -> nlohmann::json {
            nlohmann::json algorithms = nlohmann::json::array();
            for (const auto &hash : ContentRegistry::Hashes::impl::getHashes()) {
                const auto unlocalized = std::string(hash->getUnlocalizedName().get());
                const auto shortName = unlocalized.substr(unlocalized.rfind('.') + 1);

                // Probe the hash to list the output functions it exposes. Some hashes
                // define a single primary function, others define a primary plus
                // alternatives (e.g. "sha256" and "sha256.hex").
                nlohmann::json functions = nlohmann::json::array();
                for (const auto &baseName : { unlocalized, shortName, std::string("default") }) {
                    try {
                        auto fn = hash->create(baseName);
                        functions.push_back(fn.getName());
                    } catch (...) {
                        // Not all hashes expose a 'default' function; skip.
                    }
                }

                algorithms.push_back({
                    { "id",         shortName },
                    { "name",       unlocalized },
                    { "functions",  functions }
                });
            }

            nlohmann::json result = {
                { "count",       algorithms.size() },
                { "algorithms",  algorithms }
            };
            return makeResult(result);
        });

        // 3) demangle_symbol - Itanium / MSVC / Rust / D via trace::demangle. Pure read.
        ContentRegistry::MCP::registerTool(romfs::get("mcp/tools/demangle_symbol.json").string(), [](const nlohmann::json &data) -> nlohmann::json {
            const auto mangled = data.at("symbol").get<std::string>();
            if (mangled.empty())
                throw std::runtime_error("symbol must not be empty");

            const auto demangled = trace::demangle(mangled);
            // trace::demangle returns the input unchanged when it fails, so an
            // identity result is a reliable failure signal. We also try the
            // underscore-prefix and the _Z-stripped variants it tries internally
            // so the LLM gets a clean answer even on platform-prefixed symbols.
            const bool changed = (demangled != mangled);
            const auto demangledUnderscored = trace::demangle(std::string("_") + mangled);
            const auto demangledZStripped = trace::demangle(std::string("_Z") + mangled);
            const bool recognized = changed || (demangledUnderscored != std::string("_") + mangled) || (demangledZStripped != std::string("_Z") + mangled);

            nlohmann::json result = {
                { "symbol",          mangled },
                { "demangled",       demangled },
                { "recognized",      recognized }
            };
            return makeResult(result);
        });

        // 4) copy_bytes_as - format a region with one of the registered DataFormatter entries.
        //    Pure read.
        ContentRegistry::MCP::registerTool(romfs::get("mcp/tools/copy_bytes_as.json").string(), [](const nlohmann::json &data) -> nlohmann::json {
            auto provider = getActiveProvider();

            const auto format = data.value("format", "c");
            const auto address = data.value("address", u64(0));
            const auto size = clampRegion(provider, address, data.value("size", u64(0)));

            // Build a friendly-name -> unlocalized-name table from the registry.
            // The formatters are registered with unlocalized names like
            // 'hex.builtin.view.hex_editor.copy.c'; we expose short names ('c',
            // 'cpp', 'rust', 'python', etc.) and accept both.
            const auto &entries = ContentRegistry::DataFormatter::impl::getExportMenuEntries();
            const ContentRegistry::DataFormatter::impl::ExportMenuEntry *selected = nullptr;
            std::string selectedUnlocalized;
            for (const auto &entry : entries) {
                const auto unlocalized = std::string(entry.unlocalizedName.get());
                // Accept either the short form (e.g. "c") or the full unlocalized form
                if (unlocalized == format) {
                    selected = &entry;
                    selectedUnlocalized = unlocalized;
                    break;
                }
                const auto shortName = unlocalized.substr(unlocalized.rfind('.') + 1);
                if (shortName == format) {
                    selected = &entry;
                    selectedUnlocalized = unlocalized;
                    break;
                }
            }
            if (selected == nullptr) {
                // Build a helpful error listing all available short names.
                std::string available;
                for (const auto &entry : entries) {
                    const auto unlocalized = std::string(entry.unlocalizedName.get());
                    available += unlocalized.substr(unlocalized.rfind('.') + 1);
                    available += ", ";
                }
                throw std::runtime_error(fmt::format(
                    "Unknown format '{}'. Available formats: {}", format, available));
            }

            const auto output = selected->callback(provider, address, size, false);
            nlohmann::json result = {
                { "format",     selectedUnlocalized },
                { "address",    address },
                { "size",       size },
                { "output",     output }
            };
            return makeResult(result);
        });

        // 5) generate_report - run all registered Reports generators and aggregate.
        //    Reports may touch overlays (e.g. overlay list), which are main-thread state,
        //    so this tool runs on the main thread.
        ContentRegistry::MCP::registerTool(romfs::get("mcp/tools/generate_report.json").string(), [](const nlohmann::json &) -> nlohmann::json {
            return runOnMainThread([] {
                getActiveProvider();

                nlohmann::json sections = nlohmann::json::array();
                std::string combined;
                for (const auto &generator : ContentRegistry::Reports::impl::getGenerators()) {
                    const auto section = generator.callback(ImHexApi::Provider::get());
                    if (section.empty())
                        continue;
                    sections.push_back(section);
                    combined += section;
                    combined += "\n\n";
                }

                nlohmann::json result = {
                    { "section_count",  sections.size() },
                    { "report",         combined },
                    { "sections",       sections }
                };
                return makeResult(result);
            });
        });

        // 6) update_bookmark - ImHexApi::Bookmarks has only add/remove/getEntries,
        //    so 'update' is implemented as remove(old_id) + add(new fields). The new
        //    bookmark gets a fresh id; we return both so the LLM can update its
        //    bookmarks table. [M] (mutates bookmark list).
        ContentRegistry::MCP::registerTool(romfs::get("mcp/tools/update_bookmark.json").string(), [](const nlohmann::json &data) -> nlohmann::json {
            const auto id = data.at("id").get<u64>();
            // Optional fields: any of name/comment/color may be omitted to leave unchanged.
            // address and size are NOT mutable in v1 (would invalidate downstream annotations).
            // To change range, the LLM should remove + add a new one.
            const auto newName = data.value("name", std::string{});
            const auto newComment = data.value("comment", std::string{});
            const auto newColor = data.value("color", u32(0xFFFFFFFF));

            return runOnMainThread([id, newName, newComment, newColor] {
                getActiveProvider();

                // Find the old bookmark so we can preserve its address and size.
                auto entries = ImHexApi::Bookmarks::getEntries();
                const auto it = std::ranges::find_if(entries, [id](const auto &e) { return e.id == id; });
                if (it == entries.end())
                    throw std::runtime_error(fmt::format("No bookmark with ID {} found in the current data source", id));

                const auto address = it->region.getStartAddress();
                const auto size = it->region.getSize();

                ImHexApi::Bookmarks::remove(id);
                const auto newId = ImHexApi::Bookmarks::add(address, size, newName, newComment, newColor);

                nlohmann::json result = {
                    { "id",          newId },
                    { "old_id",      id },
                    { "address",     address },
                    { "size",        size },
                    { "name",        newName },
                    { "comment",     newComment },
                    { "color",       newColor }
                };
                return makeResult(result);
            });
        });

        // 7) fill_range - write a repeated byte value (or pattern) over [address, address+size).
        //    [M] (mutates the provider). Streams in 1 MiB chunks to avoid huge allocs.
        ContentRegistry::MCP::registerTool(romfs::get("mcp/tools/fill_range.json").string(), [](const nlohmann::json &data) -> nlohmann::json {
            auto provider = getActiveProvider();
            if (!provider->isWritable())
                throw std::runtime_error("The current data source is read-only. Use open_memory or open_file with a writable provider.");

            const auto address = data.at("address").get<u64>();
            const auto size    = data.at("size").get<u64>();
            if (size == 0)
                throw std::runtime_error("size must be > 0");
            const auto clampedSize = clampRegion(provider, address, size);

            // 'value' may be a single byte (0..255) or a multi-byte pattern.
            // We accept either an integer (single byte) or a string (raw bytes).
            std::vector<u8> pattern;
            if (data.contains("pattern")) {
                const auto &raw = data.at("pattern").get<std::string>();
                pattern.assign(raw.begin(), raw.end());
            } else {
                const auto v = data.value("value", u8(0));
                pattern = { v };
            }
            if (pattern.empty())
                throw std::runtime_error("fill pattern must not be empty");

            return runOnMainThread([provider, address, clampedSize, pattern]() -> nlohmann::json {
                // Tile the pattern into a chunk-sized buffer and write it
                // repeatedly. We don't read-modify-write (preserves correct
                // semantics if the user fills a range that overlaps itself).
                constexpr size_t ChunkSize = 1_MiB;
                std::vector<u8> chunk(ChunkSize);
                for (size_t i = 0; i < chunk.size(); i += pattern.size()) {
                    const auto remaining = std::min(pattern.size(), chunk.size() - i);
                    std::memcpy(chunk.data() + i, pattern.data(), remaining);
                }

                u64 bytesWritten = 0;
                for (u64 offset = 0; offset < clampedSize; offset += ChunkSize) {
                    const auto toWrite = std::min<size_t>(ChunkSize, clampedSize - offset);
                    provider->write(address + offset, chunk.data(), toWrite);
                    bytesWritten += toWrite;
                }

                nlohmann::json result = {
                    { "handle",       provider->getID() },
                    { "address",      address },
                    { "size",         bytesWritten },
                    { "pattern_hex",  crypt::encode16({ pattern.begin(), pattern.end() }) }
                };
                return makeResult(result);
            });
        });

        // 8) create_view - create a ViewProvider over a sub-range of the current provider.
        //    The view is read-only (ViewProvider::isWritable() returns false by design),
        //    so this is safe for an agent to use to inspect a region without mutating
        //    the source. [M] (mutates the provider list).
        ContentRegistry::MCP::registerTool(romfs::get("mcp/tools/create_view.json").string(), [](const nlohmann::json &data) -> nlohmann::json {
            const auto address = data.at("address").get<u64>();
            const auto size = data.at("size").get<u64>();
            const auto name = data.value("name", std::string{});

            return runOnMainThread([address, size, name]() -> nlohmann::json {
                auto *baseProvider = getActiveProvider();
                if (size == 0)
                    throw std::runtime_error("size must be > 0");
                const auto baseSize = baseProvider->getActualSize();
                if (address >= baseSize)
                    throw std::runtime_error(fmt::format("Address 0x{:X} is out of range, the data source is 0x{:X} bytes large", address, baseSize));
                if (address + size > baseSize)
                    throw std::runtime_error(fmt::format("Range [0x{:X}, 0x{:X}) is out of range, the data source is 0x{:X} bytes large", address, address + size, baseSize));

                // ViewProvider is "hex.builtin.provider.view" per builtin code paths
                // (e.g. view_bookmarks.cpp:402).
                auto newProvider = ImHexApi::Provider::createProvider("hex.builtin.provider.view", true);
                if (auto *view = dynamic_cast<ViewProvider*>(newProvider.get()); view != nullptr) {
                    view->setProvider(address, size, baseProvider);
                    if (!name.empty())
                        view->setName(name);
                    ImHexApi::Provider::openProvider(newProvider);

                    nlohmann::json result = {
                        { "handle",       newProvider->getID() },
                        { "name",         view->getName() },
                        { "address",      address },
                        { "size",         size },
                        { "base_handle",  baseProvider->getID() },
                        { "read_only",    true }
                    };
                    return makeResult(result);
                }
                throw std::runtime_error("Failed to create ViewProvider (createProvider returned a non-View type)");
            });
        });

        // ====================================================================
        // PHASE 4A — Hex Editor Highlighting & Selection
        // ====================================================================

        // 1) add_highlight — color-code a region in the hex editor.
        //    [M] (mutates hex editor state).
        ContentRegistry::MCP::registerTool(romfs::get("mcp/tools/add_highlight.json").string(), [](const nlohmann::json &data) -> nlohmann::json {
            const auto address = data.at("address").get<u64>();
            const auto size    = data.at("size").get<u64>();
            const auto color   = data.value("color", u32(0xFF0000FF));
            const auto type    = data.value("type", std::string("background"));

            if (size == 0)
                throw std::runtime_error("size must be > 0");

            return runOnMainThread([address, size, color, type]() -> nlohmann::json {
                auto *provider = getActiveProvider();
                const auto providerSize = provider->getActualSize();
                if (address >= providerSize)
                    throw std::runtime_error(fmt::format("Address 0x{:X} is out of range, the data source is 0x{:X} bytes large", address, providerSize));
                if (address + size > providerSize)
                    throw std::runtime_error(fmt::format("Range [0x{:X}, 0x{:X}) is out of range, the data source is 0x{:X} bytes large", address, address + size, providerSize));

                const Region region { address, size };
                u32 id = 0;
                if (type == "background")
                    id = ImHexApi::HexEditor::addBackgroundHighlight(region, color);
                else if (type == "foreground")
                    id = ImHexApi::HexEditor::addForegroundHighlight(region, color);
                else
                    throw std::runtime_error(fmt::format("Unknown highlight type '{}'. Supported types are 'background' and 'foreground'", type));

                nlohmann::json result = {
                    { "id",      id },
                    { "address", address },
                    { "size",    size },
                    { "color",   color },
                    { "type",    type }
                };
                return makeResult(result);
            });
        });

        // 2) remove_highlight — remove a highlight by its unique ID.
        //    [M] (mutates hex editor state).
        ContentRegistry::MCP::registerTool(romfs::get("mcp/tools/remove_highlight.json").string(), [](const nlohmann::json &data) -> nlohmann::json {
            const auto id = data.at("id").get<u32>();

            return runOnMainThread([id]() -> nlohmann::json {
                getActiveProvider();

                // Try background first, then foreground. One of them will succeed.
                const auto &bg = ImHexApi::HexEditor::impl::getBackgroundHighlights();
                const auto &fg = ImHexApi::HexEditor::impl::getForegroundHighlights();
                const bool inBg = bg.contains(id);
                const bool inFg = fg.contains(id);

                if (!inBg && !inFg)
                    throw std::runtime_error(fmt::format("No highlight with ID {} found", id));

                if (inBg)
                    ImHexApi::HexEditor::removeBackgroundHighlight(id);
                if (inFg)
                    ImHexApi::HexEditor::removeForegroundHighlight(id);

                nlohmann::json result = {
                    { "id",      id },
                    { "removed", true }
                };
                return makeResult(result);
            });
        });

        // 3) list_highlights — enumerate all active highlights.
        //    Pure read.
        ContentRegistry::MCP::registerTool(romfs::get("mcp/tools/list_highlights.json").string(), [](const nlohmann::json &) -> nlohmann::json {
            return runOnMainThread([]() -> nlohmann::json {
                auto provider = getActiveProvider();

                nlohmann::json highlights = nlohmann::json::array();
                for (const auto &[id, hl] : ImHexApi::HexEditor::impl::getBackgroundHighlights()) {
                    highlights.push_back({
                        { "id",      id },
                        { "address", hl.getRegion().address },
                        { "size",    hl.getRegion().size },
                        { "color",   hl.getColor() },
                        { "type",    "background" }
                    });
                }
                for (const auto &[id, hl] : ImHexApi::HexEditor::impl::getForegroundHighlights()) {
                    highlights.push_back({
                        { "id",      id },
                        { "address", hl.getRegion().address },
                        { "size",    hl.getRegion().size },
                        { "color",   hl.getColor() },
                        { "type",    "foreground" }
                    });
                }

                nlohmann::json result = {
                    { "handle",     provider->getID() },
                    { "highlights", highlights },
                    { "count",      highlights.size() }
                };
                return makeResult(result);
            });
        });

        // 4) set_selection — set the hex editor's current selection.
        //    [M] (mutates hex editor state).
        ContentRegistry::MCP::registerTool(romfs::get("mcp/tools/set_selection.json").string(), [](const nlohmann::json &data) -> nlohmann::json {
            const auto address = data.at("address").get<u64>();
            const auto size    = data.at("size").get<u64>();

            if (size == 0)
                throw std::runtime_error("size must be > 0");

            return runOnMainThread([address, size]() -> nlohmann::json {
                auto *provider = getActiveProvider();
                const auto providerSize = provider->getActualSize();
                if (address >= providerSize)
                    throw std::runtime_error(fmt::format("Address 0x{:X} is out of range, the data source is 0x{:X} bytes large", address, providerSize));
                if (address + size > providerSize)
                    throw std::runtime_error(fmt::format("Range [0x{:X}, 0x{:X}) is out of range, the data source is 0x{:X} bytes large", address, address + size, providerSize));

                ImHexApi::HexEditor::setSelection(address, size, provider);

                nlohmann::json result = {
                    { "address", address },
                    { "size",    size }
                };
                return makeResult(result);
            });
        });

        // 5) get_selection — read the hex editor's current selection.
        //    Pure read.
        ContentRegistry::MCP::registerTool(romfs::get("mcp/tools/get_selection.json").string(), [](const nlohmann::json &) -> nlohmann::json {
            return runOnMainThread([]() -> nlohmann::json {
                getActiveProvider();

                const auto selection = ImHexApi::HexEditor::getSelection();
                nlohmann::json result = {
                    { "valid", selection.has_value() }
                };
                if (selection.has_value()) {
                    result["address"] = selection->getRegion().address;
                    result["size"]    = selection->getRegion().size;
                } else {
                    result["address"] = nullptr;
                    result["size"]    = nullptr;
                }
                return makeResult(result);
            });
        });

        // 6) add_tooltip — add a hover tooltip to a region.
        //    [M] (mutates hex editor state).
        ContentRegistry::MCP::registerTool(romfs::get("mcp/tools/add_tooltip.json").string(), [](const nlohmann::json &data) -> nlohmann::json {
            const auto address = data.at("address").get<u64>();
            const auto size    = data.at("size").get<u64>();
            const auto text    = data.at("text").get<std::string>();
            const auto color   = data.value("color", u32(0xFFFFFFFF));

            if (size == 0)
                throw std::runtime_error("size must be > 0");

            return runOnMainThread([address, size, text, color]() -> nlohmann::json {
                auto *provider = getActiveProvider();
                const auto providerSize = provider->getActualSize();
                if (address >= providerSize)
                    throw std::runtime_error(fmt::format("Address 0x{:X} is out of range, the data source is 0x{:X} bytes large", address, providerSize));
                if (address + size > providerSize)
                    throw std::runtime_error(fmt::format("Range [0x{:X}, 0x{:X}) is out of range, the data source is 0x{:X} bytes large", address, address + size, providerSize));

                const Region region { address, size };
                const auto id = ImHexApi::HexEditor::addTooltip(region, text, color);

                nlohmann::json result = {
                    { "id",      id },
                    { "address", address },
                    { "size",    size },
                    { "text",    text },
                    { "color",   color }
                };
                return makeResult(result);
            });
        });

        // 7) remove_tooltip — remove a tooltip by its unique ID.
        //    [M] (mutates hex editor state).
        ContentRegistry::MCP::registerTool(romfs::get("mcp/tools/remove_tooltip.json").string(), [](const nlohmann::json &data) -> nlohmann::json {
            const auto id = data.at("id").get<u32>();

            return runOnMainThread([id]() -> nlohmann::json {
                getActiveProvider();

                const auto &tips = ImHexApi::HexEditor::impl::getTooltips();
                if (!tips.contains(id))
                    throw std::runtime_error(fmt::format("No tooltip with ID {} found", id));

                ImHexApi::HexEditor::removeTooltip(id);

                nlohmann::json result = {
                    { "id",      id },
                    { "removed", true }
                };
                return makeResult(result);
            });
        });
    }

}
