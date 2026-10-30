using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using CyberAgent.DTOs;
using CyberAgent.Services;

namespace CyberAgent.Controllers;

[ApiController]
[Route("api/[controller]")]
[Authorize]
public class SecurityController : ControllerBase
{
    private readonly SecurityService _svc;
    public SecurityController(SecurityService svc) => _svc = svc;
    private int UserId => int.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier)!);

    [HttpPost("scan-logs")]
    public Task<IActionResult> ScanLogs(LogScanDto dto) =>
        Guard(dto.Content, 200_000, () => _svc.ScanLogsAsync(UserId, dto));

    [HttpPost("scan-url")]
    public Task<IActionResult> ScanUrl(UrlScanDto dto) =>
        Guard(dto.Url, 2_000, () => _svc.ScanUrlAsync(UserId, dto));

    [HttpPost("scan-email")]
    public Task<IActionResult> ScanEmail(EmailScanDto dto) =>
        Guard(dto.Body, 50_000, () => _svc.ScanEmailAsync(UserId, dto));

    [HttpPost("scan-password")]
    public Task<IActionResult> ScanPassword(PasswordScanDto dto) =>
        Guard(dto.Password, 256, () => _svc.ScanPasswordAsync(UserId, dto));

    [HttpGet("dashboard")]
    public async Task<IActionResult> Dashboard() => Ok(await _svc.GetDashboardAsync(UserId));

    [HttpGet("reports")]
    public async Task<IActionResult> Reports([FromQuery] int page = 1, [FromQuery] int pageSize = 10) =>
        Ok(await _svc.GetReportsAsync(UserId, Math.Max(page, 1), Math.Clamp(pageSize, 1, 50)));

    [HttpGet("reports/{id}")]
    public async Task<IActionResult> Report(int id)
    {
        var r = await _svc.GetReportAsync(UserId, id);
        return r == null ? NotFound() : Ok(r);
    }

    [HttpDelete("reports/{id}")]
    public async Task<IActionResult> Delete(int id) =>
        await _svc.DeleteReportAsync(UserId, id) ? NoContent() : NotFound();

    private async Task<IActionResult> Guard(string? input, int maxLength, Func<Task<ScanReportDto>> action)
    {
        if (string.IsNullOrWhiteSpace(input)) return BadRequest("Input is required.");
        if (input.Length > maxLength) return BadRequest($"Input too long (max {maxLength} characters).");
        try { return Ok(await action()); }
        catch (HttpRequestException) { return StatusCode(502, "Security agent is unavailable."); }
    }
}
