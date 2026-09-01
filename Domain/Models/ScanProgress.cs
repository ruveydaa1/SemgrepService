namespace SemgrepService.Domain.Models;

public class ScanProgress
{
    public int AssetId { get; set; }

    public int ScanRunId { get; set; }

    public string Status { get; set; } = string.Empty;

    public string Message { get; set; } = string.Empty;

    public DateTime Timestamp { get; set; }
}