using AuthService.Services;
using Microsoft.EntityFrameworkCore;

namespace AuthService.Models;

public class AppDbContext : DbContext
{
    public AppDbContext(DbContextOptions<AppDbContext> options) : base(options)
    {

    }

    public DbSet<User> Users { get; set; }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        PasswordHashing.HashPassword("SecurePass123");

        modelBuilder.Entity<User>().HasKey(u => u.Id);
        modelBuilder.Entity<User>().Property(u => u.Username).IsRequired().HasMaxLength(100);
        modelBuilder.Entity<User>().Property(u => u.PasswordHash).IsRequired().HasMaxLength(256);
        modelBuilder.Entity<User>().Property(u => u.Role).IsRequired().HasMaxLength(50);

        modelBuilder.Entity<User>().HasData(
            new User { Id = 1, Username = "admin", PasswordHash = PasswordHashing.HashPassword("SecurePass123"), Role = "Admin" },
            new User { Id = 2, Username = "user", PasswordHash = PasswordHashing.HashPassword("Password1"), Role = "User" }
        );
    }
}
