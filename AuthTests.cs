using System;
using System.Net;
using System.Net.Http;
using System.Net.Http.Json;
using System.Threading.Tasks;
using FluentAssertions;
using Microsoft.AspNetCore.Mvc.Testing;
using SafeVault.Controllers;
using Xunit;

namespace SafeVault.Tests
{
    public class AuthTests : IClassFixture<WebApplicationFactory<Program>>
    {
        private readonly HttpClient _client;

        public AuthTests(WebApplicationFactory<Program> factory)
        {
            // create a client based on the real application; the in-memory database
            // defined in Program.cs will be used automatically.
            _client = factory.CreateClient();
        }

        /// <summary>
        /// Helper type that mirrors the AuthController.AuthResponse class so that
        /// we can deserialize JSON responses.
        /// </summary>
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

        [Fact]
        public async Task Register_NewUser_ReturnsSuccessAndTokens()
        {
            var request = new LoginRequest
            {
                Email = "integration@example.com",
                Password = "TestPassword123"
            };

            var response = await _client.PostAsJsonAsync("/api/auth/register", request);
            response.StatusCode.Should().Be(HttpStatusCode.OK);

            var body = await response.Content.ReadFromJsonAsync<AuthResponse>();
            body.Should().NotBeNull();
            body!.Success.Should().BeTrue();
            body.AccessToken.Should().NotBeNullOrEmpty();
            body.RefreshToken.Should().NotBeNullOrEmpty();
        }

        [Fact]
        public async Task Register_DuplicateEmail_ReturnsBadRequest()
        {
            var request = new LoginRequest
            {
                Email = "alice@example.com", // seeded in Program.cs
                Password = "password123"
            };

            var response = await _client.PostAsJsonAsync("/api/auth/register", request);
            response.StatusCode.Should().Be(HttpStatusCode.BadRequest);

            var body = await response.Content.ReadFromJsonAsync<AuthResponse>();
            body?.Success.Should().BeFalse();
            body?.Message.Should().Contain("already registered");
        }

        [Theory]
        [InlineData("alice@example.com", "password123", true)]
        [InlineData("alice@example.com", "wrongpassword", false)]
        [InlineData("nonexistent@example.com", "whatever", false)]
        public async Task Login_VariousCredentials_BehaviorMatchesExpectation(string email, string password, bool shouldSucceed)
        {
            var request = new LoginRequest
            {
                Email = email,
                Password = password
            };

            var response = await _client.PostAsJsonAsync("/api/auth/login", request);

            if (shouldSucceed)
            {
                response.StatusCode.Should().Be(HttpStatusCode.OK);
                var body = await response.Content.ReadFromJsonAsync<AuthResponse>();
                body.Should().NotBeNull();
                body!.Success.Should().BeTrue();
                body.AccessToken.Should().NotBeNullOrEmpty();
            }
            else
            {
                // unauthorized should be returned for bad credentials
                response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
                var body = await response.Content.ReadFromJsonAsync<AuthResponse>();
                body?.Success.Should().BeFalse();
            }
        }
    }
}