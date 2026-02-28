namespace SafeVault.Models
{
    /// <summary>
    /// Custom application user model for storing app-specific data.
    /// ASP.NET Identity (IdentityUser) handles authentication/password management.
    /// </summary>
    public class User
    {
        public int Id { get; set; }
        public string Username { get; set; } = null!;
        public string? Email { get; set; }
        public DateTime CreatedAt { get; set; }

        // kept for backwards compatibility with existing bcrypt hashes
        // new logins use IdentityUser managed by ASP.NET Identity
        public string? PasswordHash { get; set; }
    }
}