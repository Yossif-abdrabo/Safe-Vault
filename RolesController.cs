using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace SafeVault.Controllers
{
    /// <summary>
    /// Sample endpoints demonstrating role-based authorization.
    /// You can call these after authenticating and including a JWT that contains the
    /// user's roles (issued by /api/auth/login in this sample).
    /// </summary>
    [ApiController]
    [Route("api/[controller]")]
    public class RolesController : ControllerBase
    {
        [HttpGet("admin")]
        [Authorize(Roles = "Admin")]
        public IActionResult AdminOnly()
        {
            return Ok(new { message = "Hello Admin - you have full access." });
        }

        [HttpGet("user")]
        [Authorize(Roles = "User")]
        public IActionResult UserOnly()
        {
            return Ok(new { message = "Hello User - you have standard access." });
        }

        [HttpGet("guest")]
        [Authorize(Roles = "Guest")]
        public IActionResult GuestOnly()
        {
            return Ok(new { message = "Hello Guest - your permissions are limited." });
        }

        // you can also enforce policies instead of raw role names
        [HttpGet("admin-policy")]
        [Authorize(Policy = "AdminsOnly")]
        public IActionResult AdminUsingPolicy() => AdminOnly();
    }
}
