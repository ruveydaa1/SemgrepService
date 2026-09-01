namespace SemgrepService.Domain.Models;

public class ScanRequest
{
    public int AssetId { get; set; }

    public string Source { get; set; } = string.Empty;

    public string Scanner { get; set; } = string.Empty;

    public int ScanRunId { get; set; }
}