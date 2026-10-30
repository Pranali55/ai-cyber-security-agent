namespace CyberAgent.Models;

public class User
{
    public int Id { get; set; }
    public string Name { get; set; } = string.Empty;
    public string Email { get; set; } = string.Empty;
    public string PasswordHash { get; set; } = string.Empty;
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
}

public class ScanReport
{
    public int Id { get; set; }
    public int UserId { get; set; }
    public string Type { get; set; } = string.Empty;          // Logs, Url, Email, Password
    public string InputPreview { get; set; } = string.Empty;  // never contains passwords
    public string Severity { get; set; } = "Info";
    public int RiskScore { get; set; }
    public string Summary { get; set; } = string.Empty;
    public string FindingsJson { get; set; } = "[]";
    public string RecommendationsJson { get; set; } = "[]";
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
}
