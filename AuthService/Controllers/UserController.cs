using AuthService.DTOs;
using AuthService.Models;
using AuthService.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;

namespace AuthService.Controllers
{
    /// <summary>
    /// Controller for managing user-related operations such as registration, login, and updates.
    /// </summary>
    [ApiController]
    [Route("api/[controller]")]
    public class UserController : ControllerBase
    {
        private readonly AppDbContext _context;
        private readonly AuthServices _authService;

        /// <summary>
        /// Initializes a new instance of the <see cref="UserController"/> class.
        /// </summary>
        /// <param name="context">The database context.</param>
        /// <param name="authService">The authentication service.</param>
        public UserController(AppDbContext context, AuthServices authService)
        {
            _context = context;
            _authService = authService;
        }

        /// <summary>
        /// Registers a new user and generates a JWT token.
        /// </summary>
        /// <param name="request">The user registration details.</param>
        /// <returns>A JWT token for the newly registered user.</returns>
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
                Role = request.Role // Default role for new users
            };

            _context.Users.Add(newUser);
            await _context.SaveChangesAsync();

            var token = _authService.GenerateJwtToken(newUser);
            return Ok(token);
        }

        /// <summary>
        /// Authenticates a user and generates a JWT token.
        /// </summary>
        /// <param name="request">The login details.</param>
        /// <returns>A JWT token for the authenticated user.</returns>
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

        /// <summary>
        /// Verifies the current JWT token and generates a new one.
        /// </summary>
        /// <returns>A new JWT token for the authenticated user.</returns>
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

        /// <summary>
        /// Updates the details of the authenticated user.
        /// </summary>
        /// <param name="request">The updated user details.</param>
        /// <returns>A success message if the update is successful.</returns>
        [HttpPut("update")]
        [Authorize]
        public async Task<ActionResult> Update([FromBody] UserDto request)
        {
            // Get the user's ID from the JWT token claims
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

            // Update the username if a new one is provided.
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

            // Update the password if a new one is provided.
            if (!string.IsNullOrEmpty(request.Password))
            {
                user.PasswordHash = PasswordHashing.HashPassword(request.Password);
            }

            _context.Users.Update(user);
            await _context.SaveChangesAsync();

            return Ok($"User with ID {userId} updated successfully.");
        }

        /// <summary>
        /// Accesses a resource restricted to admin users.
        /// </summary>
        /// <returns>A success message if the user has admin access.</returns>
        [HttpGet("admin-only")]
        [Authorize(Roles = "Admin")]
        public ActionResult<string> AdminOnly()
        {
            return Ok("You have access to the admin-only resource.");
        }
    }
}
