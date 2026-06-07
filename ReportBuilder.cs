using System;
using System.Linq;
using System.Text;

namespace HardwareDiagnosticsTool
{
    public static class ReportBuilder
    {
        private const int MAX_SCORE_CAP = 50; // Must match the cap in DiagnosticMetrics

        /// <summary>
        /// Generates the complete diagnostic report.
        /// </summary>
        /// <param name="metrics">Diagnostic metrics and evidence collected.</param>
        /// <param name="isAdmin">Indicates whether the program runs with admin rights.</param>
        /// <returns>Formatted report string.</returns>
        public static string BuildReport(DiagnosticMetrics metrics, bool isAdmin)
        {
            int totalScore = metrics.CpuScore + metrics.MemoryScore + metrics.DiskScore + metrics.PowerScore + metrics.GpuScore;
            string suspectHardware = DetermineSuspectHardware(metrics, totalScore);

            StringBuilder report = new StringBuilder();
            report.AppendLine("=======================================================================");
            report.AppendLine("             Windows Notebook Unexpected Reboot Diagnostic Report         ");
            report.AppendLine("=======================================================================");
            report.AppendLine($"Generated On      : {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            report.AppendLine("Scan Range        : BSOD Kernels, WHEA Hardware Architecture, Power Logs, Storage Integrity");
            report.AppendLine("-------------------------------------------------------------------------");
            report.AppendLine("[System Health Execution Metrics]");

            if (!isAdmin)
            {
                report.AppendLine("   ⚠️ [Privilege Notice] Running without Administrator rights. Deeper log structures (e.g., specific WHEA logs) may be restricted by UAC.");
            }

            if (metrics.Details.Count > 0)
            {
                foreach (var detail in metrics.Details) report.AppendLine($"   {detail}");
            }
            else
            {
                report.AppendLine("   No major kernel-level anomalies calculated in the database.");
            }

            report.AppendLine("-------------------------------------------------------------------------");
            report.AppendLine("[Preliminary Strategic Conclusion]");
            report.AppendLine($"Suspected Component At Fault: {suspectHardware}");
            report.AppendLine("-------------------------------------------------------------------------");
            report.AppendLine($"[Hardware Instability Metrics Matrix (Capped at {MAX_SCORE_CAP} Points)]");
            report.AppendLine($"   Memory Subsystem (RAM) : {metrics.MemoryScore} Points");
            report.AppendLine($"   Processor Core   (CPU) : {metrics.CpuScore} Points");
            report.AppendLine($"   Storage Media (SSD/HDD): {metrics.DiskScore} Points");
            report.AppendLine($"   Power & Thermal Rails  : {metrics.PowerScore} Points");
            report.AppendLine($"   Graphics Adapter (GPU) : {metrics.GpuScore} Points");
            report.AppendLine("-------------------------------------------------------------------------");
            report.AppendLine("[Low-Level Forensic Evidence Logs]");

            if (metrics.Evidence.Count == 0)
            {
                report.AppendLine("   No clear low-level telemetry available. Persistent random reboots without logs typically imply zero-latency power rail dropouts.");
            }
            else
            {
                foreach (var evidence in metrics.Evidence) report.AppendLine($"   {evidence}");
            }

            report.AppendLine("-------------------------------------------------------------------------");
            report.AppendLine("[Actionable Remediation Checklist]");
            AppendChecklist(report, suspectHardware);
            report.AppendLine("=========================================================================");

            return report.ToString();
        }

        private static string DetermineSuspectHardware(DiagnosticMetrics metrics, int totalScore)
        {
            if (totalScore <= 0)
                return "No definitive hardware failure markers found (Likely caused by unstable drivers, third-party software conflicts, or system corruption).";

            var hardwareMatrix = new[]
            {
                new { Name = "Processor (CPU) Defect or Unstable VCore Voltage Supply", Score = metrics.CpuScore },
                new { Name = "Memory (RAM) Physical Degradation or Defective Contacts", Score = metrics.MemoryScore },
                new { Name = "Storage (SSD/HDD) Controller Failure or Interface Interruption", Score = metrics.DiskScore },
                new { Name = "Power Supply / Motherboard VRM Failure, or Thermal Trip Shutdown", Score = metrics.PowerScore },
                new { Name = "Discrete Graphics (GPU) Hardware Failure or Bad PCIe Connection", Score = metrics.GpuScore }
            };

            var topMatch = hardwareMatrix.OrderByDescending(h => h.Score).First();
            return topMatch.Score >= 2 ? topMatch.Name : "No definitive hardware failure markers found (Likely caused by unstable drivers, third-party software conflicts, or system corruption).";
        }

        private static void AppendChecklist(StringBuilder report, string suspectHardware)
        {
            if (suspectHardware.Contains("Memory"))
            {
                report.AppendLine("  1. Execute a deep-scan loop via MemTest86 (Bootable USB) or run the native Windows Memory Diagnostic tool.");
                report.AppendLine("  2. If running a dual-channel configuration, pull one module out and alternate sockets to test absolute stability.");
                report.AppendLine("  3. Clean the gold contacts on the RAM module using a non-static eraser and ensure it re-seats firmly.");
            }
            else if (suspectHardware.Contains("Processor"))
            {
                report.AppendLine("  1. Audit thermal charts immediately under load to detect structural thermal throttling or dry thermal paste.");
                report.AppendLine("  2. If any undervolting (Offset) or Overclocking profiles are deployed in BIOS, clear CMOS to restore hardware factory defaults.");
                report.AppendLine("  3. Check the OEM support page for urgent BIOS/UEFI microcode patches addressing CPU voltage rail fluctuations.");
            }
            else if (suspectHardware.Contains("Storage"))
            {
                report.AppendLine("  1. Download CrystalDiskInfo or manufacturer software to evaluate NVMe health parameters, checking specifically for 0E (Media Errors) indicators.");
                report.AppendLine("  2. Reseat the M.2 SSD in its slot and verify if the thermal pad is intact to counter high controller heat-death cycles.");
            }
            else if (suspectHardware.Contains("Power"))
            {
                report.AppendLine("  1. Verify if reboots only materialize under battery operation. Failing lithium battery cells often fail to deliver immediate burst currents.");
                report.AppendLine("  2. Perform heavy stress testing via AIDA64 / Prime95. Sudden power cutouts under high synthetic power draws isolate VRM/Adapter load limits.");
                report.AppendLine("  3. Clear fan blockages and re-apply premium thermal paste to rule out sudden safety-induced hardware shutdowns.");
            }
            else if (suspectHardware.Contains("Graphics"))
            {
                report.AppendLine("  1. Perform a clean GPU driver swap via Display Driver Uninstaller (DDU) in Safe Mode, then deploy the latest enterprise WHQL stable driver.");
                report.AppendLine("  2. Benchmark 3D heavy workflows via FurMark. Immediate display drops or freezes separate stable runtime kernels from GPU core logic drops.");
            }
            else
            {
                report.AppendLine("  1. If this issue is highly prevalent across an identical batch of enterprise machines with Bugcheck 0, scrutinize systemic motherboard structural bugs.");
                report.AppendLine("  2. Investigate low-level driver stack interceptors such as kernel filters added by outdated anti-virus configurations.");
            }
        }
    }
}
