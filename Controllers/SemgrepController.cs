using Microsoft.AspNetCore.Mvc;
using SemgrepService.Application.Interfaces;
using SemgrepService.Domain.Models;

namespace SemgrepService.Controllers;

[ApiController]
[Route("api/semgrep")]
public class SemgrepController : ControllerBase
{
    private readonly ISemgrepService _semgrepService;

    public SemgrepController(ISemgrepService semgrepService)
    {
        _semgrepService = semgrepService;
    }

    [HttpPost("scan")]
    public async Task<IActionResult> Scan(
        [FromBody] ScanRequest request)
    {
        var result =
            await _semgrepService.ScanAsync(request);

        return Ok(result);
    }
}