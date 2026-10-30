using Microsoft.EntityFrameworkCore;
using CyberAgent.Models;

namespace CyberAgent.Data;

public class AppDbContext : DbContext
{
    public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }

    public DbSet<User> Users => Set<User>();
    public DbSet<ScanReport> Reports => Set<ScanReport>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<User>().HasIndex(u => u.Email).IsUnique();
        modelBuilder.Entity<ScanReport>().HasIndex(r => r.UserId);
    }
}
