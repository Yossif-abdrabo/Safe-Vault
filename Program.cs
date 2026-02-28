using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Hosting;
using Serilog;
using Serilog.Events;
using System.Text;
using SafeVault.Data;
using SafeVault.Models;
using SafeVault.Services;
using SafeVault.Settings;

var builder = WebApplication.CreateBuilder(args);


Log.Logger = new LoggerConfiguration()
    .MinimumLevel.Override("Microsoft", LogEventLevel.Warning)
    .Enrich.FromLogContext()
    .WriteTo.Console()
    
    .WriteTo.File(
    path: "logs/audit-.ndjson",
    rollingInterval: RollingInterval.Day,
    formatter: new Serilog.Formatting.Json.JsonFormatter())

    .CreateLogger();

builder.Host.UseSerilog();


// configure JWT settings from appsettings
builder.Services.Configure<JwtSettings>(builder.Configuration.GetSection("JwtSettings"));

var jwtSettings = builder.Configuration.GetSection("JwtSettings").Get<JwtSettings>();

builder.Services.AddDbContext<AuthDbContext>(opts =>
    opts.UseInMemoryDatabase("AuthDb"));

    
builder.Services.AddControllersWithViews(options =>
{
    options.Filters.Add(new RequireHttpsAttribute()); // applies to MVC/Razor Pages
});


// Add JWT authentication
builder.Services.AddAuthentication(options =>
{
    
    options.DefaultAuthenticateScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = CookieAuthenticationDefaults.AuthenticationScheme;

})

.AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSettings?.Secret ?? "default-secret-key-at-least-32-characters-long")),
        ValidateIssuer = true,
        ValidIssuer = jwtSettings?.Issuer ?? "SafeVault",
        ValidateAudience = true,
        ValidAudience = jwtSettings?.Audience ?? "SafeVaultUsers",
        ValidateLifetime = true,
        ClockSkew = TimeSpan.Zero
    };
});

builder.Services.AddSession();

// add identity services
builder.Services.AddIdentity<IdentityUser, IdentityRole>()
    .AddEntityFrameworkStores<AuthDbContext>()
    .AddDefaultTokenProviders();

// override default identity password requirements (optional: adjust for your needs)
builder.Services.Configure<IdentityOptions>(options =>
{
    // Password settings (can be customized)
    options.Password.RequireDigit = true;
    options.Password.RequireLowercase = true;
    options.Password.RequireNonAlphanumeric = false;
    options.Password.RequireUppercase = false;
    options.Password.RequiredLength = 6;

    // Lockout settings
    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(5);
    options.Lockout.MaxFailedAccessAttempts = 5;
    options.Lockout.AllowedForNewUsers = true;
});

// define role‑based authorization policies
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("AdminsOnly", policy => policy.RequireRole("Admin"));
    options.AddPolicy("UsersOnly", policy => policy.RequireRole("User"));
    options.AddPolicy("GuestsOnly", policy => policy.RequireRole("Guest"));
});

// configure cookie settings
builder.Services.ConfigureApplicationCookie(options =>
{
    options.Cookie.HttpOnly = true;
    options.ExpireTimeSpan = TimeSpan.FromMinutes(60);
    options.LoginPath = "/Identity/Account/Login";
    options.LogoutPath = "/Identity/Account/Logout";
    options.AccessDeniedPath = "/Identity/Account/AccessDenied";
});



builder.Services.AddScoped<AuthService>();
builder.Services.AddScoped<JwtTokenService>();
builder.Services.AddRazorPages();
builder.Services.AddControllers();

var app = builder.Build();


app.Use(async (ctx, next) =>
{
    // Attach correlation id
    var corrId = ctx.Request.Headers["x-correlation-id"].FirstOrDefault() ?? Guid.NewGuid().ToString();
    ctx.Items["CorrelationId"] = corrId;
    using (Serilog.Context.LogContext.PushProperty("correlation_id", corrId))
    {
        await next();
    }
});


app.UseForwardedHeaders(new ForwardedHeadersOptions
{
    ForwardedHeaders = ForwardedHeaders.XForwardedProto | ForwardedHeaders.XForwardedFor
});


// create roles and (optionally) seed identity users
using (var scope = app.Services.CreateScope())
{
    var services = scope.ServiceProvider;
    var ctx = services.GetRequiredService<AuthDbContext>();
    var roleManager = services.GetRequiredService<RoleManager<IdentityRole>>();
    var userManager = services.GetRequiredService<UserManager<IdentityUser>>();

    // ensure the three application roles exist
    string[] roles = new[] { "Admin", "User", "Guest" };
    foreach (var role in roles)
    {
        if (!await roleManager.RoleExistsAsync(role))
        {
            await roleManager.CreateAsync(new IdentityRole(role));
        }
    }

    // seed Identity users and assign roles (only if no users exist yet)
    if (!ctx.Users.Any())
    {
        // old custom user table seeding for backwards compatibility
        var aliceCustom = new User { Username = "alice" };
        aliceCustom.PasswordHash = BCrypt.Net.BCrypt.HashPassword("password123");
        var bobCustom = new User { Username = "bob" };
        bobCustom.PasswordHash = BCrypt.Net.BCrypt.HashPassword("qwerty");
        ctx.Users.Add(aliceCustom);
        ctx.Users.Add(bobCustom);
        ctx.SaveChanges();
    }

    // also ensure at least one Identity user exists so that login works.
    // guard against running multiple times (test host restarts reuse the same
    // in-memory database).  Instead of calling FindByEmailAsync directly (which
    // throws if more than one user with the same email exists), check the
    // Users query and only seed when the store is empty.
    if (!await userManager.Users.AnyAsync())
    {
        var admin = new IdentityUser
        {
            UserName = "alice@example.com",
            Email = "alice@example.com",
            EmailConfirmed = true
        };
        await userManager.CreateAsync(admin, "password123");
        await userManager.AddToRoleAsync(admin, "Admin");

        var normal = new IdentityUser
        {
            UserName = "bob@example.com",
            Email = "bob@example.com",
            EmailConfirmed = true
        };
        await userManager.CreateAsync(normal, "qwerty");
        await userManager.AddToRoleAsync(normal, "User");
    }
}

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();

app.UseStaticFiles();
app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

app.MapStaticAssets();
app.MapControllers();
app.MapRazorPages()
   .WithStaticAssets();



app.MapPost("/login", async (HttpContext ctx) =>
{
    var ip = ctx.Connection.RemoteIpAddress?.ToString();
    var ua = ctx.Request.Headers.UserAgent.ToString();
    var username = ctx.Request.Form["username"].ToString();

    try
    {
        // TODO: validate credentials (omitted)
        var userId = "123e4567-e89b-12d3-a456-426614174000";

        Log.Information("user.login.success {@event}",
            new {
                event_type = "user.login.success",
                timestamp = DateTime.UtcNow,
                user_id = userId,
                username = username,   // consider hashing/masking
                ip = ip,
                user_agent = ua,
                auth_method = "password+MFA"
            });

        await ctx.Response.WriteAsJsonAsync(new { ok = true });
    }
    catch (Exception ex)
    {
        Log.Warning(ex, "user.login.failure {@event}",
            new {
                event_type = "user.login.failure",
                timestamp = DateTime.UtcNow,
                username = username,
                ip = ip,
                user_agent = ua,
                failure_reason = "invalid_credentials"
            });
        ctx.Response.StatusCode = 401;
    }
});

app.MapPost("/documents/{id}/read", (HttpContext ctx, string id) =>
{
    var ip = ctx.Connection.RemoteIpAddress?.ToString();
    var userId = ctx.User?.FindFirst("sub")?.Value ?? "anonymous";
    var allowed = true; // assume your authz check

    var evt = new {
        event_type = allowed ? "resource.access" : "resource.denied",
        timestamp = DateTime.UtcNow,
        user_id = userId,
        resource_type = "document",
        resource_id = id,
        action = "read",
        ip = ip,
        policy_decision = allowed ? "allow" : "deny"
    };
    Log.Information("{@evt}", evt);

    if (!allowed)
    {
        ctx.Response.StatusCode = 403;
        return Task.CompletedTask;
    }
    return ctx.Response.WriteAsync("content");
});

app.Run();




