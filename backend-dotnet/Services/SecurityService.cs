using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using CyberAgent.Data;
using CyberAgent.DTOs;
using CyberAgent.Models;

namespace CyberAgent.Services;

public class SecurityService
{
    // The Python agent speaks snake_case JSON
    private static readonly JsonSerializerOptions AgentJson = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
        PropertyNameCaseInsensitive = true
    };

    private readonly AppDbContext _db;
    private readonly HttpClient _http;
    private readonly string _agentUrl;

    public SecurityService(AppDbContext db, HttpClient http, IConfiguration config)
    {
        _db = db;
        _http = http;
        _agentUrl = config["AgentService:BaseUrl"] ?? "http://localhost:8000";
    }

    public Task<ScanReportDto> ScanLogsAsync(int userId, LogScanDto dto) =>
        RunAsync(userId, "Logs", "logs", new { content = dto.Content }, Preview(dto.Content));

    public Task<ScanReportDto> ScanUrlAsync(int userId, UrlScanDto dto) =>
        RunAsync(userId, "Url", "url", new { url = dto.Url }, Preview(dto.Url));

    public Task<ScanReportDto> ScanEmailAsync(int userId, EmailScanDto dto) =>
        RunAsync(userId, "Email", "email", new { sender = dto.Sender, subject = dto.Subject, body = dto.Body },
            Preview($"{dto.Subject} | {dto.Sender}"));

    // Passwords are analyzed but NEVER stored
    public Task<ScanReportDto> ScanPasswordAsync(int userId, PasswordScanDto dto) =>
        RunAsync(userId, "Password", "password", new { password = dto.Password }, "[redacted]");

    public async Task<List<ScanReportSummaryDto>> GetReportsAsync(int userId, int page, int pageSize)
    {
        var items = await _db.Reports
            .Where(r => r.UserId == userId)
            .OrderByDescending(r => r.CreatedAt)
            .Skip((page - 1) * pageSize).Take(pageSize)
            .ToListAsync();
        return items.Select(ToSummary).ToList();
    }

    public async Task<ScanReportDto?> GetReportAsync(int userId, int id)
    {
        var r = await _db.Reports.FirstOrDefaultAsync(x => x.Id == id && x.UserId == userId);
        return r == null ? null : Map(r);
    }

    public async Task<bool> DeleteReportAsync(int userId, int id)
    {
        var r = await _db.Reports.FirstOrDefaultAsync(x => x.Id == id && x.UserId == userId);
        if (r == null) return false;
        _db.Reports.Remove(r);
        await _db.SaveChangesAsync();
        return true;
    }

    public async Task<DashboardDto> GetDashboardAsync(int userId)
    {
        var reports = await _db.Reports.Where(r => r.UserId == userId).ToListAsync();
        return new DashboardDto(
            reports.Count,
            reports.Count == 0 ? 0 : Math.Round(reports.Average(r => r.RiskScore), 1),
            reports.GroupBy(r => r.Severity).ToDictionary(g => g.Key, g => g.Count()),
            reports.GroupBy(r => r.Type).ToDictionary(g => g.Key, g => g.Count()),
            reports.OrderByDescending(r => r.CreatedAt).Take(5).Select(ToSummary).ToList());
    }

    private async Task<ScanReportDto> RunAsync(int userId, string type, string route, object payload, string preview)
    {
        var body = new StringContent(JsonSerializer.Serialize(payload, AgentJson), Encoding.UTF8, "application/json");
        using var response = await _http.PostAsync($"{_agentUrl}/analyze/{route}", body);
        response.EnsureSuccessStatusCode();

        var json = await response.Content.ReadAsStringAsync();
        var result = JsonSerializer.Deserialize<AgentAnalysis>(json, AgentJson)
                     ?? throw new InvalidOperationException("Empty response from security agent");

        var report = new ScanReport
        {
            UserId = userId,
            Type = type,
            InputPreview = preview,
            Severity = result.Severity,
            RiskScore = result.RiskScore,
            Summary = result.Summary,
            FindingsJson = JsonSerializer.Serialize(result.Findings),
            RecommendationsJson = JsonSerializer.Serialize(result.Recommendations)
        };
        _db.Reports.Add(report);
        await _db.SaveChangesAsync();
        return Map(report);
    }

    private static string Preview(string? text)
    {
        var t = (text ?? string.Empty).Trim();
        return t.Length > 300 ? t[..300] + "..." : t;
    }

    private static ScanReportSummaryDto ToSummary(ScanReport r) =>
        new(r.Id, r.Type, r.Severity, r.RiskScore, r.Summary, r.CreatedAt);

    private static ScanReportDto Map(ScanReport r) => new(
        r.Id, r.Type, r.InputPreview, r.Severity, r.RiskScore, r.Summary,
        JsonSerializer.Deserialize<List<FindingDto>>(r.FindingsJson) ?? new(),
        JsonSerializer.Deserialize<List<string>>(r.RecommendationsJson) ?? new(),
        r.CreatedAt);
}
