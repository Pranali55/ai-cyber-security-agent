namespace CyberAgent.DTOs;

// Auth
public record RegisterDto(string Name, string Email, string Password);
public record LoginDto(string Email, string Password);
public record AuthResponseDto(string Token, string Name, string Email);

// Scan inputs
public record LogScanDto(string Content);
public record UrlScanDto(string Url);
public record EmailScanDto(string? Sender, string? Subject, string Body);
public record PasswordScanDto(string Password);

// Results
public record FindingDto(string Type, string Severity, string Description, string? Evidence);
public record AgentAnalysis(string Severity, int RiskScore, string Summary, List<FindingDto> Findings, List<string> Recommendations);

public record ScanReportDto(int Id, string Type, string InputPreview, string Severity, int RiskScore,
    string Summary, List<FindingDto> Findings, List<string> Recommendations, DateTime CreatedAt);

public record ScanReportSummaryDto(int Id, string Type, string Severity, int RiskScore, string Summary, DateTime CreatedAt);

public record DashboardDto(int TotalScans, double AverageRisk, Dictionary<string, int> BySeverity,
    Dictionary<string, int> ByType, List<ScanReportSummaryDto> Recent);
