using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using RBAC_App.Data;
using RBAC_App.Models;
using RBAC_App.Services;
using System.Security.Claims;
using RegisterRequest = RBAC_App.Models.RegisterRequest;

namespace RBAC_App.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class UserController : ControllerBase
    {
        private readonly AppDbContext _context;
        private readonly AuthService _authService;

        public UserController(AppDbContext context, AuthService authService)
        {
            _context = context;
            _authService = authService;
        }

        // POST api/user/register
        // Allows a new user to register with the default "User" role.
        [HttpPost("register")]
        [AllowAnonymous]
        public async Task<ActionResult<string>> Register([FromBody] RegisterRequest request)
        {
            if (await _context.Users.AnyAsync(u => u.Username == request.Username))
            {
                return BadRequest("Username already exists.");
            }

            var newUser = new User
            {
                Username = request.Username,
                PasswordHash = _authService.HashPassword(request.Password!),
                Role = "User" // Default role for new users
            };

            _context.Users.Add(newUser);
            await _context.SaveChangesAsync();

            var token = _authService.GenerateJwtToken(newUser);
            return Ok(token);
        }

        // POST api/user/login
        // Authenticates a user and issues a JWT token.
        [HttpPost("login")]
        [AllowAnonymous]
        public async Task<ActionResult<string>> Login([FromBody] RegisterRequest request)
        {
            var user = await _context.Users.SingleOrDefaultAsync(u => u.Username == request.Username);

            if (user == null || !_authService.VerifyPassword(request.Password!, user.PasswordHash!))
            {
                return Unauthorized("Invalid username or password.");
            }

            var token = _authService.GenerateJwtToken(user);
            return Ok(token);
        }

        // GET api/user/verify-token
        // This endpoint verifies an existing token and issues a new one if it's valid.
        // It serves as the verification step requested by the user.
        [HttpGet("verify-token")]
        [Authorize]
        public ActionResult<string> VerifyTokenAndGetNew()
        {
            // The [Authorize] attribute itself handles the token verification.
            // If the code reaches this point, the token is already considered valid by the middleware.
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

            // Re-issue a new token for the valid user.
            var token = _authService.GenerateJwtToken(user);
            return Ok(token);
        }

        // PUT api/user/update
        // Allows a user to update their own username and password.
        // This endpoint requires authentication.
        [HttpPut("update")]
        [Authorize]
        public async Task<ActionResult> Update([FromBody] RegisterRequest request)
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
            }

            // Update the password if a new one is provided.
            if (!string.IsNullOrEmpty(request.Password))
            {
                user.PasswordHash = _authService.HashPassword(request.Password);
            }

            _context.Users.Update(user);
            await _context.SaveChangesAsync();

            return Ok($"User with ID {userId} updated successfully.");
        }

        // GET api/user/admin-only
        // This is an example of a secure endpoint that only users with the 'Admin' role can access.
        // It demonstrates the RBAC functionality.
        [HttpGet("admin-only")]
        [Authorize(Roles = "Admin")]
        public ActionResult<string> AdminOnly()
        {
            return Ok("You have access to the admin-only resource.");
        }
    }
}