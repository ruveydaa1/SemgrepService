using SemgrepService.Domain.Models;

namespace SemgrepService.Application.Interfaces;

public interface IScannerService
{
    Task<ScanResult> ScanAsync(
        ScanRequest request,
        Func<ScanProgress, Task>? onProgress = null);
}