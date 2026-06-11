#include <hex/api/content_registry/communication_interface.hpp>
#include <hex/api/imhex_api/provider.hpp>
#include <hex/providers/provider.hpp>
#include <hex/helpers/fmt.hpp>

#include <content/helpers/capstone.hpp>

#include <romfs/romfs.hpp>
#include <wolv/literals.hpp>
#include <wolv/utils/guards.hpp>

#include <nlohmann/json.hpp>

#include <algorithm>
#include <stdexcept>
#include <string>
#include <vector>

namespace hex::plugin::disasm {

    using namespace wolv::literals;

    namespace {

        constexpr size_t MaxDisassemblyBytes = 1_MiB;
        constexpr u64 MaxInstructions = 10000;

        prv::Provider* getReadableProvider() {
            auto *provider = ImHexApi::Provider::get();
            if (provider == nullptr)
                throw std::runtime_error("No data source is currently open. Use the open_file tool first.");
            if (!provider->isReadable())
                throw std::runtime_error("The current data source is not readable yet.");
            return provider;
        }

        nlohmann::json makeResult(const nlohmann::json &result) {
            return mcp::StructuredContent {
                .text = result.dump(),
                .data = result
            };
        }

        cs_opt_value parseSyntax(const std::string &syntax) {
            if (syntax == "default") return CS_OPT_SYNTAX_DEFAULT;
            if (syntax == "intel")   return CS_OPT_SYNTAX_INTEL;
            if (syntax == "att")     return CS_OPT_SYNTAX_ATT;
            if (syntax == "masm")    return CS_OPT_SYNTAX_MASM;
            if (syntax == "motorola") return CS_OPT_SYNTAX_MOTOROLA;
            throw std::runtime_error(fmt::format("Unknown syntax '{}'. Use default/intel/att/masm/motorola", syntax));
        }

    }

    void registerDisassemblerMCPTools() {
        ContentRegistry::MCP::registerTool(romfs::get("mcp/tools/list_architectures.json").string(), [](const nlohmann::json &) -> nlohmann::json {
            // Canonical architecture spec tokens understood by the disassemble tool.
            // Format: "arch[;opt1,opt2,...]"; suffix the arch with 'be'/'eb' for big-endian.
            struct ArchInfo { const char *spec; const char *description; };
            static const std::array<ArchInfo, 22> Architectures = {{
                { "x86;32bit",        "Intel x86 (use 16bit/32bit/64bit)" },
                { "x64",              "Intel x86-64 (alias of x86;64bit)" },
                { "arm",              "ARM (add ;thumb, ;cortex-m, ;armv8)" },
                { "aarch64",          "ARM64 / AArch64" },
                { "mips;32bit",       "MIPS (32bit/64bit, ;micromips, mipsbe for big-endian)" },
                { "riscv;rv32g",      "RISC-V (rv32g/rv64g, ;riscvc)" },
                { "ppc;32bit",        "PowerPC (32bit/64bit, ppcbe for big-endian)" },
                { "sparc",            "SPARC (;sparcv9, sparcbe)" },
                { "sysz",             "IBM z/Architecture (SystemZ)" },
                { "xcore",            "XMOS xCORE" },
                { "m68k",             "Motorola 68000 (;68000..;68060)" },
                { "m680x;6809",       "Motorola 680X (;6800..;hcs08)" },
                { "tms320c64x",       "TI TMS320C64x DSP" },
                { "evm",              "Ethereum VM bytecode" },
                { "wasm",             "WebAssembly" },
                { "mos65xx;6502",     "MOS 65xx (;65c02, ;65816)" },
                { "bpf",              "Berkeley Packet Filter (;bpfe)" },
                { "sh;sh4",           "Hitachi SuperH (;sh2..;sh4a)" },
                { "tricore;tc1.6",    "Infineon TriCore" },
                { "alpha",            "DEC Alpha (Capstone 6+)" },
                { "loongarch;loongarch64", "LoongArch (Capstone 6+)" },
                { "xtensa;esp32",     "Xtensa (Capstone 6+)" }
            }};

            nlohmann::json architectures = nlohmann::json::array();
            for (const auto &[spec, description] : Architectures) {
                architectures.push_back({ { "spec", spec }, { "description", description } });
            }

            nlohmann::json result = {
                { "architectures", architectures },
                { "spec_format", "arch[;option1,option2]; suffix arch with 'be' or 'eb' for big-endian (e.g. 'mipsbe;mips32r6')" },
                { "capstone_version", fmt::format("{}.{}", CS_API_MAJOR, CS_API_MINOR) }
            };
            return makeResult(result);
        });

        ContentRegistry::MCP::registerTool(romfs::get("mcp/tools/disassemble.json").string(), [](const nlohmann::json &data) -> nlohmann::json {
            auto provider = getReadableProvider();

            const auto architectureSpec = data.at("architecture").get<std::string>();
            const auto address   = data.value("address", u64(0));
            const auto imageBase = data.value("image_base", address);
            const auto maxInstructions = std::clamp<u64>(data.value("max_instructions", u64(256)), 1, MaxInstructions);

            if (address >= provider->getActualSize())
                throw std::runtime_error(fmt::format("Address 0x{:X} is out of range (data source is 0x{:X} bytes)", address, provider->getActualSize()));

            u64 size = data.contains("size") ? data.at("size").get<u64>() : (provider->getActualSize() - address);
            size = std::min<u64>({ size, provider->getActualSize() - address, MaxDisassemblyBytes });

            // Parse the architecture spec into a capstone arch + mode (handles endianness + sub-modes)
            auto [arch, mode] = CapstoneDisassembler::stringToSettings(architectureSpec);

            csh handle = 0;
            if (cs_open(arch, mode, &handle) != CS_ERR_OK)
                throw std::runtime_error(fmt::format("Failed to initialize the disassembler for '{}' (architecture/mode may be unsupported by this Capstone build)", architectureSpec));
            ON_SCOPE_EXIT { cs_close(&handle); };

            cs_option(handle, CS_OPT_SKIPDATA, CS_OPT_ON);
            if (data.contains("syntax"))
                cs_option(handle, CS_OPT_SYNTAX, parseSyntax(data.at("syntax").get<std::string>()));

            std::vector<u8> buffer(size);
            provider->read(address, buffer.data(), buffer.size());

            cs_insn *instruction = cs_malloc(handle);
            ON_SCOPE_EXIT { cs_free(instruction, 1); };

            nlohmann::json instructions = nlohmann::json::array();

            const u8 *code = buffer.data();
            size_t remaining = buffer.size();
            u64 virtualAddress = imageBase;

            while (remaining > 0 && instructions.size() < maxInstructions) {
                const u64 fileOffset = address + (buffer.size() - remaining);
                if (!cs_disasm_iter(handle, &code, &remaining, &virtualAddress, instruction))
                    break;

                std::string bytes;
                for (u16 i = 0; i < instruction->size; i++)
                    bytes += fmt::format("{:02X} ", instruction->bytes[i]);
                if (!bytes.empty())
                    bytes.pop_back();

                instructions.push_back({
                    { "address", instruction->address },
                    { "offset", fileOffset },
                    { "size", instruction->size },
                    { "bytes", bytes },
                    { "mnemonic", instruction->mnemonic },
                    { "operands", instruction->op_str }
                });
            }

            const u64 bytesConsumed = buffer.size() - remaining;

            nlohmann::json result = {
                { "handle", provider->getID() },
                { "architecture", architectureSpec },
                { "image_base", imageBase },
                { "instructions", instructions },
                { "count", instructions.size() },
                { "bytes_consumed", bytesConsumed },
                { "truncated", instructions.size() >= maxInstructions && bytesConsumed < buffer.size() }
            };
            return makeResult(result);
        });
    }

}
