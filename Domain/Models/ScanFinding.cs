namespace SemgrepService.Domain.Models;

public class ScanFinding
{
    public string CheckId { get; set; } = string.Empty;

    public string Path { get; set; } = string.Empty;

    public int StartLine { get; set; }

    public int StartColumn { get; set; }

    public int EndLine { get; set; }

    public int EndColumn { get; set; }

    public string Message { get; set; } = string.Empty;

    public string Category { get; set; } = string.Empty;

    public string Severity { get; set; } = string.Empty;

    public string Confidence { get; set; } = string.Empty;

    public string Impact { get; set; } = string.Empty;

    public string Cwe { get; set; } = string.Empty;

    public string Owasp { get; set; } = string.Empty;

    public string VulnerabilityClass { get; set; } = string.Empty;

    public string Reference { get; set; } = string.Empty;
}