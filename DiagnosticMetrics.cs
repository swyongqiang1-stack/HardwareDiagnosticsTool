using System;
using System.Collections.Generic;

namespace HardwareDiagnosticsTool
{
    public class DiagnosticMetrics
    {
        private int _cpuScore, _memoryScore, _diskScore, _powerScore, _gpuScore;

        public int CpuScore { get => _cpuScore; set => _cpuScore = Math.Min(value, MAX_SCORE_CAP); }
        public int MemoryScore { get => _memoryScore; set => _memoryScore = Math.Min(value, MAX_SCORE_CAP); }
        public int DiskScore { get => _diskScore; set => _diskScore = Math.Min(value, MAX_SCORE_CAP); }
        public int PowerScore { get => _powerScore; set => _powerScore = Math.Min(value, MAX_SCORE_CAP); }
        public int GpuScore { get => _gpuScore; set => _gpuScore = Math.Min(value, MAX_SCORE_CAP); }

        public List<string> Evidence { get; } = new List<string>();
        public List<string> Details { get; } = new List<string>();

        // Internal cap constant used for score limiting
        private const int MAX_SCORE_CAP = 50;
    }
}
