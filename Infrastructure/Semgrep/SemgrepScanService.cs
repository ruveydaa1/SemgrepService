using System.Diagnostics;
using System.Text.Json;
using SemgrepService.Application.Interfaces;
using SemgrepService.Domain.Models;

namespace SemgrepService.Infrastructure.Semgrep;

public class SemgrepScanService : ISemgrepService
{
    public async Task<ScanResult> ScanAsync(ScanRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.Source))
        {
            return new ScanResult
            {
                AssetId = request.AssetId,
                ScanRunId = request.ScanRunId,
                Success = false,
                Scanner = "Semgrep",
                Source = request.Source,
                Error = "Scan source belirtilmedi."
            };
        }

        if (!Uri.TryCreate(
                request.Source,
                UriKind.Absolute,
                out var repositoryUri) ||
            (repositoryUri.Scheme != Uri.UriSchemeHttp &&
             repositoryUri.Scheme != Uri.UriSchemeHttps))
        {
            return new ScanResult
            {
                AssetId = request.AssetId,
                ScanRunId = request.ScanRunId,
                Success = false,
                Scanner = "Semgrep",
                Source = request.Source,
                Error = "Geçerli bir repository URL'si belirtilmelidir."
            };
        }

        string? tempDirectory = null;

        try
        {
            tempDirectory = Path.Combine(
                Path.GetTempPath(),
                "SemgrepService",
                Guid.NewGuid().ToString());

            Directory.CreateDirectory(tempDirectory);

            // Repository'yi geçici klasöre clone eder.
            var gitStartInfo = new ProcessStartInfo
            {
                FileName = "git",
                Arguments =
                    $"clone --depth 1 \"{request.Source}\" \"{tempDirectory}\"",

                RedirectStandardOutput = true,
                RedirectStandardError = true,

                UseShellExecute = false,
                CreateNoWindow = true
            };

            using var gitProcess = new Process
            {
                StartInfo = gitStartInfo
            };

            gitProcess.Start();

            var gitOutputTask =
                gitProcess.StandardOutput.ReadToEndAsync();

            var gitErrorTask =
                gitProcess.StandardError.ReadToEndAsync();

            await gitProcess.WaitForExitAsync();

            var gitOutput = await gitOutputTask;
            var gitError = await gitErrorTask;

            if (gitProcess.ExitCode != 0)
            {
                return new ScanResult
                {
                    AssetId = request.AssetId,
                    ScanRunId = request.ScanRunId,
                    Success = false,
                    Scanner = "Semgrep",
                    Source = request.Source,
                    Error =
                        $"Git repository clone edilemedi: {gitError}"
                };
            }

            // Clone edilen repository üzerinde Semgrep çalıştırılır.
            var semgrepStartInfo = new ProcessStartInfo
            {
                FileName = "semgrep",
                Arguments =
                    $"--config=auto --json --exclude=.git \"{tempDirectory}\"",

                RedirectStandardOutput = true,
                RedirectStandardError = true,

                UseShellExecute = false,
                CreateNoWindow = true
            };

            using var semgrepProcess = new Process
            {
                StartInfo = semgrepStartInfo
            };

            semgrepProcess.Start();

            var outputTask =
                semgrepProcess.StandardOutput.ReadToEndAsync();

            var errorTask =
                semgrepProcess.StandardError.ReadToEndAsync();

            await semgrepProcess.WaitForExitAsync();

            var output = await outputTask;
            var error = await errorTask;

            var findings = ParseFindings(output);

            return new ScanResult
            {
                AssetId = request.AssetId,
                ScanRunId = request.ScanRunId,
                Success =
                    semgrepProcess.ExitCode == 0 ||
                    semgrepProcess.ExitCode == 1,
                Scanner = "Semgrep",
                Source = request.Source,
                Output = string.Empty,
                Error = error,
                Findings = findings
            };
        }
        catch (Exception ex)
        {
            return new ScanResult
            {
                AssetId = request.AssetId,
                ScanRunId = request.ScanRunId,
                Success = false,
                Scanner = "Semgrep",
                Source = request.Source,
                Error =
                    $"Semgrep çalıştırılırken hata oluştu: {ex.Message}"
            };
        }
        finally
        {
            // Geçici repository klasörünü temizler.
            if (!string.IsNullOrWhiteSpace(tempDirectory) &&
                Directory.Exists(tempDirectory))
            {
                try
                {
                    Directory.Delete(
                        tempDirectory,
                        recursive: true);
                }
                catch (Exception ex)
                {
                    Console.WriteLine(
                        $"Geçici repository klasörü silinemedi: {ex.Message}");
                }
            }
        }
    }

    private List<ScanFinding> ParseFindings(string output)
    {
        var findings = new List<ScanFinding>();

        if (string.IsNullOrWhiteSpace(output))
        {
            return findings;
        }

        try
        {
            using var document =
                JsonDocument.Parse(output);

            if (!document.RootElement.TryGetProperty(
                    "results",
                    out var results))
            {
                return findings;
            }

            foreach (var result in results.EnumerateArray())
            {
                var finding = new ScanFinding
                {
                    CheckId = GetString(
                        result,
                        "check_id"),

                    Path = GetString(
                        result,
                        "path"),

                    Message = GetNestedString(
                        result,
                        "extra",
                        "message"),

                    Severity = GetNestedString(
                        result,
                        "extra",
                        "severity"),

                    Confidence = GetNestedString(
                        result,
                        "extra",
                        "metadata",
                        "confidence"),

                    Impact = GetNestedString(
                        result,
                        "extra",
                        "metadata",
                        "impact"),

                    Category = GetNestedString(
                        result,
                        "extra",
                        "metadata",
                        "category"),

                    Cwe = GetMetadataValue(
                        result,
                        "cwe"),

                    Owasp = GetMetadataValue(
                        result,
                        "owasp"),

                    VulnerabilityClass = GetMetadataValue(
                        result,
                        "vulnerability_class"),

                    Reference = GetMetadataValue(
                        result,
                        "references")
                };

                if (result.TryGetProperty(
                        "start",
                        out var start))
                {
                    finding.StartLine =
                        GetInt(start, "line");

                    finding.StartColumn =
                        GetInt(start, "col");
                }

                if (result.TryGetProperty(
                        "end",
                        out var end))
                {
                    finding.EndLine =
                        GetInt(end, "line");

                    finding.EndColumn =
                        GetInt(end, "col");
                }

                findings.Add(finding);
            }
        }
        catch (JsonException)
        {
            // Semgrep çıktısı geçerli JSON değilse
            // findings boş bırakılır.
        }

        return findings;
    }

    private static string GetString(
        JsonElement element,
        string propertyName)
    {
        if (element.TryGetProperty(
                propertyName,
                out var property))
        {
            return property.GetString() ?? string.Empty;
        }

        return string.Empty;
    }

    private static int GetInt(
        JsonElement element,
        string propertyName)
    {
        if (element.TryGetProperty(
                propertyName,
                out var property) &&
            property.TryGetInt32(out var value))
        {
            return value;
        }

        return 0;
    }

    private static string GetNestedString(
        JsonElement element,
        params string[] properties)
    {
        var current = element;

        foreach (var propertyName in properties)
        {
            if (!current.TryGetProperty(
                    propertyName,
                    out current))
            {
                return string.Empty;
            }
        }

        return current.ValueKind == JsonValueKind.String
            ? current.GetString() ?? string.Empty
            : string.Empty;
    }

    private static string GetMetadataValue(
        JsonElement result,
        string propertyName)
    {
        if (!result.TryGetProperty(
                "extra",
                out var extra))
        {
            return string.Empty;
        }

        if (!extra.TryGetProperty(
                "metadata",
                out var metadata))
        {
            return string.Empty;
        }

        if (!metadata.TryGetProperty(
                propertyName,
                out var property))
        {
            return string.Empty;
        }

        if (property.ValueKind == JsonValueKind.String)
        {
            return property.GetString() ?? string.Empty;
        }

        if (property.ValueKind == JsonValueKind.Array)
        {
            return string.Join(
                ", ",
                property.EnumerateArray()
                    .Select(x => x.GetString())
                    .Where(x =>
                        !string.IsNullOrWhiteSpace(x)));
        }

        return property.ToString();
    }
}