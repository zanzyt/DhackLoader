using Newtonsoft.Json;

namespace Unturend_Injector
{
    public static class Logger
    {
        private const string LogFile = "InjectionLog.json";
        private static readonly List<LogEntry> LogEntries = [];

        public static void Log(string message, ConsoleColor color)
        {
            Console.ForegroundColor = color;
            Console.WriteLine($"{DateTime.Now:HH:mm:ss} - {message}");
            Console.ResetColor();

            // Существующая логика записи в файл
            LogEntry entry = new() { Timestamp = DateTime.Now, Message = message };
            LogEntries.Add(entry);
            File.WriteAllText(LogFile, JsonConvert.SerializeObject(LogEntries, Formatting.Indented));
        }
        public class LogEntry
        {
            public DateTime Timestamp { get; set; }
            public string Message { get; set; }
        }
    }
}
