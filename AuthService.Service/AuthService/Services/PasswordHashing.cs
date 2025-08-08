using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using System.Security.Cryptography;

namespace AuthService.Services
{
    public class PasswordHashing
    {
        public static string HashPassword(string password)
        {
            // Generate a 128-bit salt
            byte[] salt = new byte[128 / 8];
            RandomNumberGenerator.Fill(salt);

            // Derive a 256-bit hash using PBKDF2 with HMACSHA256 and 100,000 iterations
            byte[] hash = KeyDerivation.Pbkdf2(
                password: password,
                salt: salt,
                prf: KeyDerivationPrf.HMACSHA256,
                iterationCount: 100000,
                numBytesRequested: 256 / 8);

            // Combine salt and hash for storage (e.g., in a database)
            return $"{Convert.ToBase64String(salt)}:{Convert.ToBase64String(hash)}";
        }

        public static bool VerifyPassword(string password, string storedHash)
        {
            // Split stored hash into salt and hash components
            string[] parts = storedHash.Split(':');
            if (parts.Length != 2) return false;

            byte[] salt = Convert.FromBase64String(parts[0]);
            byte[] expectedHash = Convert.FromBase64String(parts[1]);

            // Recompute hash from provided password and stored salt
            byte[] actualHash = KeyDerivation.Pbkdf2(
                password: password,
                salt: salt,
                prf: KeyDerivationPrf.HMACSHA256,
                iterationCount: 100000,
                numBytesRequested: expectedHash.Length);

            // Compare hashes securely (constant-time comparison)
            return CryptographicOperations.FixedTimeEquals(actualHash, expectedHash);
        }
    }

    //// Usage
    //string password = "SecurePass123";
    //        string hashed = PasswordHasher.HashPassword(password);
    //Console.WriteLine($"Hashed: {hashed}");

    //bool isValid = PasswordHasher.VerifyPassword("SecurePass123", hashed);
    //    Console.WriteLine($"Valid: {isValid}");  // True

}
