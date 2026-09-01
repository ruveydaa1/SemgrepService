namespace SemgrepService.Domain.Models;

public class ScanResult
{
    public int AssetId { get; set; }

    public int ScanRunId { get; set; }

    public bool Success { get; set; }

    public string Scanner { get; set; } = string.Empty;

    public string Source { get; set; } = string.Empty;

    public string Output { get; set; } = string.Empty;

    public string Error { get; set; } = string.Empty;

    public List<ScanFinding> Findings { get; set; } = new();
}