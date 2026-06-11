#include <hex/api/content_registry/communication_interface.hpp>
#include <hex/api/imhex_api/provider.hpp>
#include <hex/providers/provider.hpp>
#include <hex/helpers/fmt.hpp>

#include <content/yara_rule.hpp>

#include <romfs/romfs.hpp>
#include <wolv/io/file.hpp>
#include <wolv/utils/string.hpp>

#include <nlohmann/json.hpp>

#include <stdexcept>
#include <string>

namespace hex::plugin::yara {

    namespace {

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

    }

    void registerYaraMCPTools() {
        // libyara is ref-counted; one init at plugin load is sufficient for the lifetime
        // of the process (the YARA view init/cleanup as a matched pair around this).
        YaraRule::init();

        ContentRegistry::MCP::registerTool(romfs::get("mcp/tools/yara_scan.json").string(), [](const nlohmann::json &data) -> nlohmann::json {
            auto provider = getReadableProvider();

            const bool hasRule = data.contains("rule");
            const bool hasPath = data.contains("rule_path");
            if (hasRule == hasPath)
                throw std::runtime_error("Provide exactly one of 'rule' (inline YARA rule text) or 'rule_path' (a .yar file path)");

            // YaraRule holds an atomic and is non-copyable/movable, so build the rule text
            // up front and construct it exactly once.
            std::string ruleContent;
            if (hasRule) {
                ruleContent = data.at("rule").get<std::string>();
            } else {
                auto path = data.at("rule_path").get<std::string>();
                wolv::io::File file(std::fs::path(path), wolv::io::File::Mode::Read);
                if (!file.isValid())
                    throw std::runtime_error(fmt::format("Could not open YARA rule file '{}'", path));
                ruleContent = file.readString();
            }

            YaraRule rule(ruleContent);

            // Optional sub-region; default to the whole provider
            const u64 providerSize = provider->getActualSize();
            const u64 address = data.value("address", provider->getBaseAddress());
            u64 size = data.contains("size") ? data.at("size").get<u64>() : providerSize;
            size = std::min<u64>(size, (provider->getBaseAddress() + providerSize) - address);

            auto matchResult = rule.match(provider, Region { address, size_t(size) });

            if (!matchResult.has_value()) {
                const auto &error = matchResult.error();
                const char *type = "runtime_error";
                switch (error.type) {
                    using enum YaraRule::Error::Type;
                    case CompileError: type = "compile_error"; break;
                    case RuntimeError: type = "runtime_error"; break;
                    case Interrupted:  type = "interrupted";   break;
                }
                throw std::runtime_error(fmt::format("YARA {}: {}", type, error.message));
            }

            const auto &result = matchResult.value();

            nlohmann::json rules = nlohmann::json::array();
            for (const auto &matchedRule : result.matchedRules) {
                nlohmann::json matches = nlohmann::json::array();
                for (const auto &match : matchedRule.matches) {
                    if (match.wholeDataMatch) {
                        matches.push_back({ { "whole_data", true } });
                    } else {
                        matches.push_back({
                            { "variable", match.variable },
                            { "address", match.region.getStartAddress() },
                            { "size", match.region.getSize() }
                        });
                    }
                }

                rules.push_back({
                    { "identifier", matchedRule.identifier },
                    { "tags", matchedRule.tags },
                    { "metadata", matchedRule.metadata },
                    { "matches", matches },
                    { "match_count", matches.size() }
                });
            }

            nlohmann::json json = {
                { "handle", provider->getID() },
                { "matched_rules", rules },
                { "rule_count", rules.size() },
                { "console", wolv::util::combineStrings(result.consoleMessages, "\n") }
            };
            return makeResult(json);
        });
    }

}
