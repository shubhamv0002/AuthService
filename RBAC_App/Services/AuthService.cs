using Microsoft.IdentityModel.Tokens;
using RBAC_App.Data;
using RBAC_App.Models;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace RBAC_App.Services
{
    public class AuthService
    {
        private readonly AppDbContext? _context;
        private readonly IConfiguration? _configuration;

        public AuthService(AppDbContext? context, IConfiguration? configuration)
        {
            _context = context;
            _configuration = configuration;
        }

        // Hashes a plain-text password using a simple method.
        // A real-world application would use a more robust hashing library like BCrypt.
        public string HashPassword(string password)
        {
            return Convert.ToBase64String(Encoding.UTF8.GetBytes(password));
        }

        // Verifies a plain-text password against a hashed password.
        public bool VerifyPassword(string password, string hashedPassword)
        {
            return HashPassword(password) == hashedPassword;
        }

        // Generates a JWT token for a given user.
        public string GenerateJwtToken(User user)
        {
            if (_configuration == null)
            {
                throw new InvalidOperationException("Configuration not available.");
            }
            var jwtSettings = _configuration.GetSection("Jwt");
            var key = Encoding.ASCII.GetBytes(jwtSettings["Key"] ?? "");
            var issuer = jwtSettings["Issuer"];
            var audience = jwtSettings["Audience"];

            // Define the claims for the JWT token.
            // These claims contain information about the user, including their role.
            var claims = new[]
            {
                new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
                new Claim(ClaimTypes.Name, user.Username!),
                new Claim(ClaimTypes.Role, user.Role!),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                Expires = DateTime.UtcNow.AddMinutes(60), // Token expires in 60 minutes
                Issuer = issuer,
                Audience = audience,
                SigningCredentials = new SigningCredentials(
                    new SymmetricSecurityKey(key),
                    SecurityAlgorithms.HmacSha256Signature
                )
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            var token = tokenHandler.CreateToken(tokenDescriptor);

            return tokenHandler.WriteToken(token);
        }
    }
}
