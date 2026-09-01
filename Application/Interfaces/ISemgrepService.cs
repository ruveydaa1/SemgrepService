using SemgrepService.Domain.Models;

namespace SemgrepService.Application.Interfaces;

public interface ISemgrepService
{
    Task<ScanResult> ScanAsync(ScanRequest request);
}