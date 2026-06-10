#if !defined(OS_WEB)

    #include <hex/api/events/requests_lifecycle.hpp>
    #include <hex/api/imhex_api/system.hpp>
    #include <hex/api/content_registry/communication_interface.hpp>
    #include <hex/api/task_manager.hpp>
    #include <hex/helpers/logger.hpp>
    #include <hex/ui/imgui_imhex_extensions.h>
    #include <wolv/utils/guards.hpp>

    #include <init/run.hpp>
    #include <init/tasks.hpp>
    #include <window.hpp>

    #include <GLFW/glfw3.h>

    #include <thread>

    namespace hex::init {

        bool g_mcpServerMode = false;

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

                // Run init tasks directly without splash window
                for (const auto &[name, task, async, running] : init::getInitTasks()) {
                    log::info("Running init task: {}", name);
                    bool result = task();
                    if (!result) {
                        log::error("Init task '{}' failed!", name);
                        return EXIT_FAILURE;
                    }
                }

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