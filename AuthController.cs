using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using SafeVault.Services;

namespace SafeVault.Controllers
{
    /// <summary>
    /// API controller for authentication and token issuance
    /// </summary>
    [ApiController]
    [RequireHttps]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly JwtTokenService _jwtTokenService;
        private readonly ILogger<AuthController> _logger;

        public AuthController(
            UserManager<IdentityUser> userManager,
            SignInManager<IdentityUser> signInManager,
            JwtTokenService jwtTokenService,
            ILogger<AuthController> logger)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _jwtTokenService = jwtTokenService;
            _logger = logger;
        }

        /// <summary>
        /// Request body for login
        /// </summary>
        public class LoginRequest
        {
            [Required(ErrorMessage = "Email is required")]
            [EmailAddress]
            public string Email { get; set; } = string.Empty;

            [Required(ErrorMessage = "Password is required")]
            public string Password { get; set; } = string.Empty;
        }

        /// <summary>
        /// Response with access token
        /// </summary>
        public class AuthResponse
        {
            public bool Success { get; set; }
            public string? Message { get; set; }
            public string? AccessToken { get; set; }
            public string? RefreshToken { get; set; }
            public DateTime? ExpiresAt { get; set; }
        }

        /// <summary>
        /// Login endpoint - returns JWT token
        /// POST /api/auth/login
        /// </summary>
        [HttpPost("login")]
        [AllowAnonymous]
        public async Task<ActionResult<AuthResponse>> Login([FromBody] LoginRequest request)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(new AuthResponse 
                { 
                    Success = false, 
                    Message = "Invalid email or password format" 
                });
            }

            // Find user by email
            var user = await _userManager.FindByEmailAsync(request.Email);
            if (user == null)
            {
                _logger.LogWarning($"Login attempt with non-existent email: {request.Email}");
                return Unauthorized(new AuthResponse 
                { 
                    Success = false, 
                    Message = "Invalid email or password" 
                });
            }

            // Validate password
            var result = await _signInManager.PasswordSignInAsync(user, request.Password, false, false);
            if (!result.Succeeded)
            {
                _logger.LogWarning($"Failed login attempt for user: {user.Email}");
                return Unauthorized(new AuthResponse 
                { 
                    Success = false, 
                    Message = "Invalid email or password" 
                });
            }

            // Get user roles
            var roles = await _userManager.GetRolesAsync(user);

            // Generate tokens
            var accessToken = _jwtTokenService.GenerateAccessToken(user.Id, user.Email ?? user.UserName ?? "user", roles);
            var refreshToken = _jwtTokenService.GenerateRefreshToken();
            var expiresAt = DateTime.UtcNow.AddMinutes(60); // Match to JWT expiration

            _logger.LogInformation($"Successful login for user: {user.Email}");

            return Ok(new AuthResponse
            {
                Success = true,
                Message = "Login successful",
                AccessToken = accessToken,
                RefreshToken = refreshToken,
                ExpiresAt = expiresAt
            });
        }

        /// <summary>
        /// Register endpoint - creates a new user account
        /// POST /api/auth/register
        /// </summary>
        [HttpPost("register")]
        [AllowAnonymous]
        public async Task<ActionResult<AuthResponse>> Register([FromBody] LoginRequest request)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(new AuthResponse 
                { 
                    Success = false, 
                    Message = "Invalid email or password format" 
                });
            }

            // Check if user already exists
            var existingUser = await _userManager.FindByEmailAsync(request.Email);
            if (existingUser != null)
            {
                return BadRequest(new AuthResponse 
                { 
                    Success = false, 
                    Message = "Email is already registered" 
                });
            }

            // Create new user
            var user = new IdentityUser
            {
                UserName = request.Email,
                Email = request.Email,
                EmailConfirmed = true
            };

            var result = await _userManager.CreateAsync(user, request.Password);
            if (!result.Succeeded)
            {
                var errors = string.Join(", ", result.Errors.Select(e => e.Description));
                _logger.LogWarning($"Registration failed: {errors}");
                return BadRequest(new AuthResponse 
                { 
                    Success = false, 
                    Message = $"Registration failed: {errors}" 
                });
            }

            // put newly registered user into the 'User' role by default
            await _userManager.AddToRoleAsync(user, "User");

            _logger.LogInformation($"New user registered: {user.Email}");

            // Auto-login after registration
            var roles = await _userManager.GetRolesAsync(user);
            var accessToken = _jwtTokenService.GenerateAccessToken(user.Id, user.Email ?? user.UserName ?? "user", roles);
            var refreshToken = _jwtTokenService.GenerateRefreshToken();
            var expiresAt = DateTime.UtcNow.AddMinutes(60);

            return Ok(new AuthResponse
            {
                Success = true,
                Message = "Registration successful",
                AccessToken = accessToken,
                RefreshToken = refreshToken,
                ExpiresAt = expiresAt
            });
        }

        /// <summary>
        /// Validate token endpoint - check if JWT is valid
        /// GET /api/auth/validate
        /// </summary>
        [HttpGet("validate")]
        [Authorize]
        public ActionResult<AuthResponse> ValidateToken()
        {
            var token = Request.Headers["Authorization"].ToString().Replace("Bearer ", "");
            var claims = _jwtTokenService.GetClaimsFromToken(token);

            if (claims == null)
            {
                return Unauthorized(new AuthResponse 
                { 
                    Success = false, 
                    Message = "Invalid token" 
                });
            }

            return Ok(new AuthResponse
            {
                Success = true,
                Message = "Token is valid",
                AccessToken = token
            });
        }

        /// <summary>
        /// Get current user info
        /// GET /api/auth/me
        /// </summary>
        [HttpGet("me")]
        [Authorize]
        public async Task<ActionResult<object>> GetCurrentUser()
        {
            var userId = User.FindFirst("oid")?.Value ?? User.FindFirst("sub")?.Value;
            if (string.IsNullOrEmpty(userId))
            {
                return Unauthorized();
            }

            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                return NotFound();
            }

            var roles = await _userManager.GetRolesAsync(user);

            return Ok(new
            {
                id = user.Id,
                email = user.Email,
                username = user.UserName,
                roles = roles
            });
        }
    }
}
