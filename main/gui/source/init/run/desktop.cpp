#if !defined(OS_WEB)

    #include <hex/api/events/requests_lifecycle.hpp>
    #include <hex/api/imhex_api/system.hpp>
    #include <hex/api/content_registry/communication_interface.hpp>
    #include <hex/api/task_manager.hpp>
    #include <hex/helpers/logger.hpp>
    #include <hex/helpers/magic.hpp>
    #include <hex/helpers/utils.hpp>
    #include <hex/helpers/default_paths.hpp>
    #include <hex/ui/imgui_imhex_extensions.h>
    #include <wolv/utils/guards.hpp>
    #include <wolv/utils/string.hpp>

    #include <init/run.hpp>
    #include <init/tasks.hpp>
    #include <window.hpp>

    #include <GLFW/glfw3.h>

    #include <filesystem>
    #include <thread>

    namespace hex::init {

        bool g_mcpServerMode = false;

        namespace {

            // Honor IMHEX_CONTENT_DIR so a headless deployment can point ImHex at a bundled
            // content directory (magic db, pattern std-library, patterns) without relying on
            // the per-user data folder. Multiple paths may be separated by the OS path
            // separator (';' on Windows, ':' elsewhere). Must run before the init tasks so
            // the directories are part of the data-path search from the start.
            void applyContentDirOverride() {
                auto value = hex::getEnvironmentVariable("IMHEX_CONTENT_DIR");
                if (!value.has_value() || value->empty())
                    return;

                #if defined(OS_WINDOWS)
                    constexpr char Separator = ';';
                #else
                    constexpr char Separator = ':';
                #endif

                std::vector<std::fs::path> paths = ImHexApi::System::getAdditionalFolderPaths();
                for (const auto &part : wolv::util::splitString(*value, std::string(1, Separator))) {
                    auto trimmed = wolv::util::trim(part);
                    if (trimmed.empty())
                        continue;

                    std::error_code error;
                    if (std::fs::exists(trimmed, error)) {
                        log::info("Adding content directory from IMHEX_CONTENT_DIR: {}", trimmed);
                        paths.emplace_back(trimmed);
                    } else {
                        log::warn("IMHEX_CONTENT_DIR entry does not exist, ignoring: {}", trimmed);
                    }
                }

                ImHexApi::System::setAdditionalFolderPaths(paths);
            }

            // The magic database ships as source files; the GUI compiles them to .mgc lazily
            // when a view needs them. Headless mode never triggers that, so identify_file /
            // suggest_patterns would see no magic db. Compile it once up front (best-effort).
            void compileMagicDatabase() {
                bool hasMagicFiles = false;
                std::error_code error;
                for (const auto &dir : paths::Magic.read()) {
                    if (std::fs::exists(dir, error) && !std::fs::is_empty(dir, error)) {
                        hasMagicFiles = true;
                        break;
                    }
                }

                if (!hasMagicFiles) {
                    log::info("No magic database files found; identify_file will use the built-in signature table. "
                              "Provision ImHex content or set IMHEX_CONTENT_DIR to enable libmagic.");
                    return;
                }

                if (magic::compile())
                    log::info("Magic database compiled successfully");
                else
                    log::warn("Failed to compile the magic database; identify_file will fall back to signatures");
            }

        }

        int runImHex() {
            // MCP Server headless mode - no GUI, just TCP server
            if (g_mcpServerMode) {
                log::info("Starting ImHex in MCP server mode (headless)");

                TaskManager::init();

                // Create a minimal ImGui context so plugins can initialize properly
                ImGui::CreateContext();

                // Provide the custom ImHex style data that themed UI code (e.g. toasts
                // triggered by provider events) expects to find on the ImGui context
                static ImGuiExt::ImHexCustomData s_imguiCustomData;
                ImGui::GetIO().UserData = &s_imguiCustomData;

                // Pick up any externally provided content directory before paths are resolved
                applyContentDirOverride();

                // Run init tasks directly without splash window
                for (const auto &[name, task, async, running] : init::getInitTasks()) {
                    log::info("Running init task: {}", name);
                    bool result = task();
                    if (!result) {
                        log::error("Init task '{}' failed!", name);
                        return EXIT_FAILURE;
                    }
                }

                // Build the magic database so libmagic-backed tools work headlessly
                compileMagicDatabase();

                // Enable the MCP server
                ContentRegistry::MCP::impl::setEnabled(true);
                log::info("MCP server enabled on port {}", hex::mcp::Server::McpInternalPort);
                log::info("Waiting for MCP connections...");

                // Keep the process alive and service main-thread work queued by MCP tools
                while (true) {
                    TaskManager::runDeferredCalls();
                    std::this_thread::sleep_for(std::chrono::milliseconds(100));
                }

                return EXIT_SUCCESS;
            }

            // Initialize GLFW
            if (!glfwInit()) {
                log::fatal("Failed to initialize GLFW!");
                std::abort();
            }
            ON_SCOPE_EXIT { glfwTerminate(); };

            bool shouldRestart = false;
            do {
                // Register an event handler that will make ImHex restart when requested
                shouldRestart = false;
                RequestRestartImHex::subscribe([&] {
                    shouldRestart = true;
                });

                // Splash window
                {
                    auto splashWindow = initializeImHex();
                    // Draw the splash window while tasks are running

                    while (true) {
                        const auto result = splashWindow->loop();
                        if (result.has_value()) {
                            if (!result.value()) {
                                ImHexApi::System::impl::addInitArgument("tasks-failed");
                            }

                            break;
                        }
                    }

                    handleFileOpenRequest();
                }

                // Main window
                {
                    Window window;
                    initializationFinished();

                    window.loop();
                }

                deinitializeImHex();
            } while (shouldRestart);

            return EXIT_SUCCESS;
        }

    }

#endif