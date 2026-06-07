using System;
using System.IO;
using System.Text;
using System.Linq;
using System.Collections.Generic;
using System.Security.Principal;
using System.Diagnostics.Eventing.Reader;
using System.Xml.Linq;

namespace HardwareDiagnosticsTool
{
    class Program
    {
        private const int MAX_LOG_PROCESSING_LIMIT = 50;
        private const int MAX_SCORE_CAP = 50; // Used for display only; actual limiting is inside DiagnosticMetrics

        static void Main(string[] args)
        {
            Console.OutputEncoding = Encoding.UTF8;
            bool isAdmin = IsAdministrator();

            if (!isAdmin)
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("[Warning] Running without Administrator privileges. Some low-level system event logs might be inaccessible.");
                Console.ResetColor();
            }

            DiagnosticMetrics metrics = new DiagnosticMetrics();

            // 3.1 Kernel-Power diagnostics (Event ID 41)
            try
            {
                var kpQuery = new EventLogQuery("System", PathType.LogName, "*[System[EventID=41]]") { ReverseDirection = true };
                using (var reader = new EventLogReader(kpQuery))
                {
                    EventRecord record;
                    int processedCount = 0;
                    int totalFound = 0;

                    while ((record = reader.ReadEvent()) != null)
                    {
                        totalFound++;

                        if (processedCount >= MAX_LOG_PROCESSING_LIMIT)
                        {
                            // Fast-forward through remaining events without parsing XML
                            while (reader.ReadEvent() != null) totalFound++;
                            break;
                        }

                        processedCount++;

                        string bugcheckCodeDec = GetEventXmlProperty(record, "BugcheckCode");
                        string powerButtonTime = GetEventXmlProperty(record, "PowerButtonTimestamp");

                        if (!string.IsNullOrEmpty(bugcheckCodeDec) && bugcheckCodeDec != "0" && long.TryParse(bugcheckCodeDec, out long codeDec))
                        {
                            string bugcheckHex = "0x" + Convert.ToString(codeDec, 16).ToUpper();
                            metrics.Evidence.Add($"Kernel-Power caught a BSOD crash. Bugcheck Code: {bugcheckHex} (Timestamp: {record.TimeCreated})");

                            switch (bugcheckHex)
                            {
                                case "0x1A": case "0x2E": case "0x4E": case "0x50": case "0x109":
                                    metrics.MemoryScore += 3;
                                    metrics.Evidence.Add($"  -> Bugcheck {bugcheckHex} is highly correlated with RAM stability issues.");
                                    break;
                                case "0x101": case "0x124":
                                    metrics.CpuScore += 4;
                                    metrics.Evidence.Add($"  -> Bugcheck {bugcheckHex} is associated with CPU core or core-voltage failure.");
                                    break;
                                case "0x7A": case "0x7B": case "0xF4": case "0xEF":
                                    metrics.DiskScore += 3;
                                    metrics.Evidence.Add($"  -> Bugcheck {bugcheckHex} signals Storage (SSD/HDD) or interface communication failure.");
                                    break;
                                case "0x116": case "0x117": case "0x119":
                                    metrics.GpuScore += 3;
                                    metrics.Evidence.Add($"  -> Bugcheck {bugcheckHex} relates to Graphics Card (GPU) or PCIe slot anomalies.");
                                    break;
                            }
                        }
                        else
                        {
                            if (powerButtonTime == "0")
                            {
                                metrics.PowerScore += 2;
                                metrics.Evidence.Add($"Instant power cut or hardware freeze detected (Bugcheck 0, No BSOD. Timestamp: {record.TimeCreated}). Commonly linked to motherboard VRMs, power adapters, or instant thermal shutdown.");
                            }
                            else
                            {
                                metrics.Evidence.Add($"Detected a manual hard shutdown initiated by the user long-pressing the power button (Timestamp: {record.TimeCreated}).");
                            }
                        }
                    }

                    if (totalFound > 0)
                    {
                        metrics.Details.Add($"Detected a total of {totalFound} unexpected reboot records (Deep analyzed latest {Math.Min(totalFound, MAX_LOG_PROCESSING_LIMIT)}).");
                    }
                }
            }
            catch (Exception ex) { LogDebugException("Kernel-Power Log Query Fail", ex); }

            // 3.2 WHEA-Logger hardware error assessment
            try
            {
                var wheaQuery = new EventLogQuery("System", PathType.LogName, "*[System[Provider[@Name='Microsoft-Windows-WHEA-Logger']]]") { ReverseDirection = true };
                using (var reader = new EventLogReader(wheaQuery))
                {
                    EventRecord record;
                    int count = 0;
                    while ((record = reader.ReadEvent()) != null)
                    {
                        count++;
                        if (count > 5)
                        {
                            while (reader.ReadEvent() != null) count++;
                            break;
                        }

                        metrics.Evidence.Add($"WHEA Hardware Log Entry (ID: {record.Id}, Timestamp: {record.TimeCreated}).");
                        string message = record.FormatDescription() ?? "";

                        if (record.Id == 18 || message.Contains("Processor", StringComparison.OrdinalIgnoreCase))
                        {
                            metrics.CpuScore += 5;
                            metrics.Evidence.Add("  -> [Recent Event] Detected CPU Architecture or Cache Hierarchy Error (Machine Check Exception).");
                        }
                        else if (record.Id == 17 || message.Contains("PCIExpress", StringComparison.OrdinalIgnoreCase))
                        {
                            metrics.GpuScore += 2;
                            metrics.DiskScore += 1;
                            metrics.Evidence.Add("  -> [Recent Event] Detected PCIe Bus Interconnect Error. May impact Discrete GPU or NVMe SSD.");
                        }
                    }
                    if (count > 0)
                    {
                        metrics.Details.Add($"WHEA (Windows Hardware Error Architecture) captured a total of {count} hardware error events.");
                    }
                }
            }
            catch (Exception ex) { LogDebugException("WHEA Log Query Fail", ex); }

            // 3.3 Memory Diagnostic logs (IDs 1102 / 1202)
            try
            {
                var memQuery = new EventLogQuery("System", PathType.LogName, "*[System[Provider[@Name='Microsoft-Windows-MemoryDiagnostics-Results'] and (EventID=1102 or EventID=1202)]]") { ReverseDirection = true };
                using (var reader = new EventLogReader(memQuery))
                {
                    EventRecord record;
                    int memEventCount = 0;
                    while ((record = reader.ReadEvent()) != null)
                    {
                        if (memEventCount >= 10) break;
                        memEventCount++;
                        metrics.MemoryScore += 10;
                        metrics.Evidence.Add($"Windows Memory Diagnostic Tool explicitly confirmed physical RAM degradation (Event ID: {record.Id}, Timestamp: {record.TimeCreated}).");
                    }
                }
            }
            catch (Exception ex) { LogDebugException("Memory Diagnostics Log Query Fail", ex); }

            // 3.4 Storage and file system integrity (NTFS / Disk errors level <= 2)
            try
            {
                var diskQuery = new EventLogQuery("System", PathType.LogName, "*[System[((Level=1 or Level=2) and (Provider[@Name='disk'] or Provider[@Name='Ntfs']))]]") { ReverseDirection = true };
                using (var reader = new EventLogReader(diskQuery))
                {
                    if (reader.ReadEvent() != null)
                    {
                        metrics.DiskScore += 2;
                        metrics.Evidence.Add("Storage subsystems reported critical driver or file-system level anomalies recently (NTFS/Disk Error).");
                    }
                }
            }
            catch (Exception ex) { LogDebugException("Disk/NTFS Log Query Fail", ex); }

            // 3.5 Critical thermal shutdown events (IDs 8624, 86)
            try
            {
                var thermalQuery = new EventLogQuery("System", PathType.LogName, "*[System[EventID=8624 or EventID=86]]") { ReverseDirection = true };
                using (var reader = new EventLogReader(thermalQuery))
                {
                    EventRecord record = reader.ReadEvent();
                    if (record != null)
                    {
                        metrics.PowerScore += 3;
                        metrics.Evidence.Add($"System triggered an emergency thermal shutdown due to exceeding safe temperature thresholds (Event ID: {record.Id}).");
                    }
                }
            }
            catch (Exception ex) { LogDebugException("Thermal Log Query Fail", ex); }

            // Build and display report
            string reportText = ReportBuilder.BuildReport(metrics, isAdmin);
            Console.WriteLine(reportText);

            // Persist report to disk
            string desktopPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Desktop), "Reboot_Hardware_Diagnosis_Report.txt");
            string tempPath = Path.Combine(Path.GetTempPath(), "Reboot_Hardware_Diagnosis_Report.txt");
            string savedPath = null;

            try
            {
                File.WriteAllText(desktopPath, reportText, Encoding.UTF8);
                savedPath = desktopPath;
            }
            catch (Exception ex)
            {
                LogDebugException("Desktop Save Fail", ex);
                try
                {
                    File.WriteAllText(tempPath, reportText, Encoding.UTF8);
                    savedPath = tempPath;
                }
                catch (Exception tex) { LogDebugException("Temp Save Fail", tex); }
            }

            if (savedPath != null)
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine($"\n[Success] Diagnostic report successfully preserved at: {savedPath}");
                Console.ResetColor();
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("[Warning] Storage persistence failed. Please copy the console data manually.");
                Console.ResetColor();
            }

            Console.WriteLine("\nPress any key to exit...");
            Console.ReadKey();
        }

        // Helper: Extract a named property from the event's XML data
        static string GetEventXmlProperty(EventRecord record, string propertyName)
        {
            try
            {
                string xmlStr = record.ToXml();
                XDocument doc = XDocument.Parse(xmlStr);
                XNamespace ns = doc.Root?.GetDefaultNamespace() ?? "http://schemas.microsoft.com/win/2004/08/events/event";

                var dataElements = doc.Root?.Element(ns + "EventData")?.Elements(ns + "Data");
                if (dataElements != null)
                {
                    var target = dataElements.FirstOrDefault(e => e.Attribute("Name")?.Value == propertyName);
                    return target?.Value;
                }
            }
            catch (Exception ex)
            {
                LogDebugException($"XML Parse Fail for {propertyName}", ex);
            }
            return null;
        }

        // Check if the process is running with administrator privileges
        static bool IsAdministrator()
        {
            using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
            {
                WindowsPrincipal principal = new WindowsPrincipal(identity);
                return principal.IsInRole(WindowsBuiltInRole.Administrator);
            }
        }

        // Log debug information (only in DEBUG builds)
        static void LogDebugException(string context, Exception ex)
        {
#if DEBUG
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Error.WriteLine($"[Debug Trace] {context}: {ex.Message}");
            Console.ResetColor();
#endif
        }
    }
}
