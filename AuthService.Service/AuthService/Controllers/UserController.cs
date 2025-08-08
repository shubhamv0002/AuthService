using AuthService.DTOs;
using AuthService.Models;
using AuthService.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;

namespace AuthService.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class UserController : ControllerBase
    {
        private readonly AppDbContext _context;
        private readonly AuthServices _authService;

        public UserController(AppDbContext context, AuthServices authService)
        {
            _context = context;
            _authService = authService;
        }

        [HttpPost("register")]
        [AllowAnonymous]
        public async Task<ActionResult<string>> Register([FromBody] UserDto request)
        {
            if (await _context.Users.AnyAsync(u => u.Username == request.Username))
            {
                return BadRequest("Username already exists.");
            }

            var newUser = new User
            {
                Username = request.Username,
                PasswordHash = PasswordHashing.HashPassword(request.Password!),
                Role = request.Role
            };

            _context.Users.Add(newUser);
            await _context.SaveChangesAsync();

            var token = _authService.GenerateJwtToken(newUser);
            return Ok(token);
        }

        [HttpPost("login")]
        [AllowAnonymous]
        public async Task<ActionResult<string>> Login([FromBody] LoginDto request)
        {
            var user = await _context.Users.SingleOrDefaultAsync(u => u.Username == request.Username);

            if (user == null || !PasswordHashing.VerifyPassword(request.Password!, user.PasswordHash!))
            {
                return Unauthorized("Invalid username or password.");
            }

            // Generate a JWT token for the authenticated user
            var token = _authService.GenerateJwtToken(user);
            return Ok(token);
        }

        [HttpGet("verify-token")]
        [Authorize]
        public ActionResult<string> VerifyTokenAndGetNew()
        {
            var userIdClaim = User.FindFirst(ClaimTypes.NameIdentifier);
            if (userIdClaim == null)
            {
                return Unauthorized("User ID not found in token.");
            }

            var userId = int.Parse(userIdClaim.Value);
            var user = _context.Users.Find(userId);

            if (user == null)
            {
                return NotFound("User not found.");
            }

            var token = _authService.GenerateJwtToken(user);
            return Ok(token);
        }

        [HttpPut("update")]
        [Authorize]
        public async Task<ActionResult> Update([FromBody] UserDto request)
        {
            // Get the user's ID from JWT token claims
            var userIdClaim = User.FindFirst(ClaimTypes.NameIdentifier);
            if (userIdClaim == null)
            {
                return Unauthorized("User ID not found in token.");
            }

            var userId = int.Parse(userIdClaim.Value);
            var user = await _context.Users.FindAsync(userId);

            if (user == null)
            {
                return NotFound("User not found.");
            }

            if (!string.IsNullOrEmpty(request.Username))
            {
                if (await _context.Users.AnyAsync(u => u.Username == request.Username && u.Id != userId))
                {
                    return BadRequest("New username is already taken.");
                }
                user.Username = request.Username;
                if (!string.IsNullOrEmpty(request.Role))
                {
                    user.Role = request.Role;
                }
            }

            if (!string.IsNullOrEmpty(request.Password))
            {
                user.PasswordHash = PasswordHashing.HashPassword(request.Password);
            }

            _context.Users.Update(user);
            await _context.SaveChangesAsync();

            return Ok($"User with ID {userId} updated successfully.");
        }

        [HttpGet("admin-only")]
        [Authorize(Roles = "Admin")]
        public ActionResult<string> AdminOnly()
        {
            return Ok("You have access to the admin-only resource.");
        }
    }
}
