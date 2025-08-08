using Microsoft.EntityFrameworkCore;
using RBAC_App.Models;
using RBAC_App.Services;

namespace RBAC_App.Data
{
    public class AppDbContext : DbContext
    {
        public AppDbContext(DbContextOptions<AppDbContext> options) : base(options)
        {
        }

        public DbSet<User> Users { get; set; }

        // Method to seed data for initial testing.
        public void SeedData()
        {
            if (!Users.Any())
            {
                // Create a basic password hasher for our seeded users
                var passwordHasher = new AuthService(null, null);

                // Seed an Admin user
                var adminPasswordHash = passwordHasher.HashPassword("admin123");
                Users.Add(new User { Id = 1, Username = "admin", PasswordHash = adminPasswordHash, Role = "Admin" });

                // Seed a regular user
                var userPasswordHash = passwordHasher.HashPassword("user123");
                Users.Add(new User { Id = 2, Username = "user", PasswordHash = userPasswordHash, Role = "User" });

                SaveChanges();
            }
        }
    }
}
