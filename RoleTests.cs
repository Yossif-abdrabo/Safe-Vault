using System;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Threading.Tasks;
using FluentAssertions;
using Microsoft.AspNetCore.Mvc.Testing;
using Xunit;

namespace SafeVault.Tests
{
    public class RoleTests : IClassFixture<WebApplicationFactory<Program>>
    {
        private readonly HttpClient _client;

        public RoleTests(WebApplicationFactory<Program> factory)
        {
            _client = factory.CreateClient();
        }

        private class AuthResponse
        {
            public bool Success { get; set; }
            public string? Message { get; set; }
            public string? AccessToken { get; set; }
            public string? RefreshToken { get; set; }
            public DateTime? ExpiresAt { get; set; }
        }

        private class LoginRequest
        {
            public string Email { get; set; } = string.Empty;
            public string Password { get; set; } = string.Empty;
        }

        private async Task<string> GetTokenAsync(string email, string password)
        {
            var req = new LoginRequest { Email = email, Password = password };
            var resp = await _client.PostAsJsonAsync("/api/auth/login", req);
            resp.StatusCode.Should().Be(HttpStatusCode.OK);
            var body = await resp.Content.ReadFromJsonAsync<AuthResponse>();
            body.Should().NotBeNull();
            return body!.AccessToken!;
        }

        private async Task<HttpResponseMessage> GetWithToken(string url, string token)
        {
            var message = new HttpRequestMessage(HttpMethod.Get, url);
            message.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            return await _client.SendAsync(message);
        }

        [Fact]
        public async Task Endpoints_WithoutToken_Return401()
        {
            var urls = new[] { "/api/roles/admin", "/api/roles/user", "/api/roles/guest", "/api/roles/admin-policy" };
            foreach (var u in urls)
            {
                var response = await _client.GetAsync(u);
                response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
            }
        }

        [Fact]
        public async Task AdminUser_CanAccessAdminAndPolicy_ButNotOthers()
        {
            var token = await GetTokenAsync("alice@example.com", "password123");

            (await GetWithToken("/api/roles/admin", token)).StatusCode.Should().Be(HttpStatusCode.OK);
            (await GetWithToken("/api/roles/admin-policy", token)).StatusCode.Should().Be(HttpStatusCode.OK);
            (await GetWithToken("/api/roles/user", token)).StatusCode.Should().Be(HttpStatusCode.Forbidden);
            (await GetWithToken("/api/roles/guest", token)).StatusCode.Should().Be(HttpStatusCode.Forbidden);
        }

        [Fact]
        public async Task NormalUser_CanAccessUserOnly()
        {
            var token = await GetTokenAsync("bob@example.com", "qwerty");

            (await GetWithToken("/api/roles/user", token)).StatusCode.Should().Be(HttpStatusCode.OK);
            (await GetWithToken("/api/roles/admin", token)).StatusCode.Should().Be(HttpStatusCode.Forbidden);
            (await GetWithToken("/api/roles/guest", token)).StatusCode.Should().Be(HttpStatusCode.Forbidden);
            (await GetWithToken("/api/roles/admin-policy", token)).StatusCode.Should().Be(HttpStatusCode.Forbidden);
        }
    }
}