using Microsoft.EntityFrameworkCore;
using JwtSecurity.Data;
using JwtSecurity.Configurations;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using JwtSecurity.Models;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using System.IdentityModel.Tokens.Jwt;
using JwtSecurity.Utilities;

var builder = WebApplication.CreateBuilder(args);

// Load environment variables
DotNetEnv.Env.Load();

// Configure JWT settings with error handling for missing environment variables
var jwtSettings = new JwtSettings
{
    Issuer = Environment.GetEnvironmentVariable("JWT_ISSUER")
        ?? throw new InvalidOperationException("JWT_ISSUER environment variable is not set."),
    Audience = Environment.GetEnvironmentVariable("JWT_AUDIENCE")
        ?? throw new InvalidOperationException("JWT_AUDIENCE environment variable is not set."),
    SecretKey = Environment.GetEnvironmentVariable("JWT_KEY")
        ?? throw new InvalidOperationException("JWT_KEY environment variable is not set."),
    ExpirationMinutes = int.TryParse(Environment.GetEnvironmentVariable("JWT_EXPIRATION_MINUTES"), out var expiration)
        ? expiration
        : throw new InvalidOperationException("JWT_EXPIRATION_MINUTES environment variable is not valid.")
};

// Add JWT authentication
builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
}).AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true, // Ensure this is true
        ValidateIssuerSigningKey = true,
        ValidIssuer = jwtSettings.Issuer,
        ValidAudience = jwtSettings.Audience,
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSettings.SecretKey)),
        ClockSkew = TimeSpan.Zero // Optional: Reduce allowed clock skew (default is 5 minutes)
    };
});


// Register authorization services
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("AdminOnly", policy => policy.RequireRole("Admin"));
    options.AddPolicy("UserOnly", policy => policy.RequireRole("User"));
});

// Configure Entity Framework and database context
builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseSqlServer(Environment.GetEnvironmentVariable("CONNECTION_STRING")
        ?? throw new InvalidOperationException("CONNECTION_STRING environment variable is not set.")));

// Add other services
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
builder.Services.AddSingleton(jwtSettings);

var app = builder.Build();

// Configure middleware
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();

// Secure test endpoint
app.MapGet("/secure", () => "This is a secure endpoint.")
    .RequireAuthorization();

// Register endpoint
app.MapPost("/register", async (RegisterRequest request, AppDbContext dbContext) =>
{
    // Check if the username already exists
    if (await dbContext.Users.AnyAsync(u => u.Username == request.Username))
    {
        return Results.BadRequest(new { Error = "Username already exists." });
    }

    // Generate a unique salt for the user
    var salt = Guid.NewGuid().ToString();

    // Hash the password with the generated salt
    var hashedPassword = Convert.ToBase64String(KeyDerivation.Pbkdf2(
        password: request.Password,
        salt: Encoding.UTF8.GetBytes(salt),
        prf: KeyDerivationPrf.HMACSHA256,
        iterationCount: 10000,
        numBytesRequested: 32));

    // Create and save the user
    var user = new User
    {
        Username = request.Username,
        PasswordHash = hashedPassword,
        Role = request.Role,
        Salt = salt
    };
    dbContext.Users.Add(user);
    await dbContext.SaveChangesAsync();

    return Results.Ok("User registered successfully.");
});


// Login endpoint
app.MapPost("/login", async (LoginRequest request, AppDbContext dbContext, JwtSettings jwtSettings) =>
{
    var user = await dbContext.Users.FirstOrDefaultAsync(u => u.Username == request.Username);
    if (user == null) return Results.Unauthorized();

    var hashedPassword = Convert.ToBase64String(KeyDerivation.Pbkdf2(
        password: request.Password,
        salt: Encoding.UTF8.GetBytes(user.Salt),
        prf: KeyDerivationPrf.HMACSHA256,
        iterationCount: 10000,
        numBytesRequested: 32));

    if (user.PasswordHash != hashedPassword) return Results.Unauthorized();

    // Generate JWT Token
    var tokenHandler = new JwtSecurityTokenHandler();
    var key = Encoding.UTF8.GetBytes(jwtSettings.SecretKey);
    var tokenDescriptor = new SecurityTokenDescriptor
    {
        Subject = new System.Security.Claims.ClaimsIdentity(new[]
        {
            new System.Security.Claims.Claim("id", user.Id.ToString()),
            new System.Security.Claims.Claim("username", user.Username),
            new System.Security.Claims.Claim("role", user.Role)
        }),
        Expires = DateTime.UtcNow.AddMinutes(jwtSettings.ExpirationMinutes),
        Issuer = jwtSettings.Issuer,
        Audience = jwtSettings.Audience,
        SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
    };

    var accessToken = tokenHandler.CreateToken(tokenDescriptor);
    var refreshToken = TokenHelper.GenerateRefreshToken();

    user.RefreshToken = refreshToken;
    user.RefreshTokenExpiryTime = DateTime.UtcNow.AddDays(7); // Refresh token valid for 7 days
    await dbContext.SaveChangesAsync();

    return Results.Ok(new
    {
        Token = tokenHandler.WriteToken(accessToken),
        RefreshToken = refreshToken
    });
});

app.MapPost("/refresh-token", async (RefreshTokenRequest request, AppDbContext dbContext, JwtSettings jwtSettings) =>
{
    var user = await dbContext.Users.FirstOrDefaultAsync(u => u.RefreshToken == request.RefreshToken);
    if (user == null || user.RefreshTokenExpiryTime <= DateTime.UtcNow)
    {
        return Results.Json(new { Error = "Invalid or expired refresh token." }, statusCode: StatusCodes.Status401Unauthorized);
    }

    // Generate new JWT Token
    var tokenHandler = new JwtSecurityTokenHandler();
    var key = Encoding.UTF8.GetBytes(jwtSettings.SecretKey);
    var tokenDescriptor = new SecurityTokenDescriptor
    {
        Subject = new System.Security.Claims.ClaimsIdentity(new[]
        {
            new System.Security.Claims.Claim("id", user.Id.ToString()),
            new System.Security.Claims.Claim("username", user.Username),
            new System.Security.Claims.Claim("role", user.Role)
        }),
        Expires = DateTime.UtcNow.AddMinutes(jwtSettings.ExpirationMinutes),
        Issuer = jwtSettings.Issuer,
        Audience = jwtSettings.Audience,
        SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
    };

    var accessToken = tokenHandler.CreateToken(tokenDescriptor);

    return Results.Ok(new
    {
        Token = tokenHandler.WriteToken(accessToken)
    });
});



// Admin-only endpoint
app.MapGet("/secure/admin-panel", () => "This is the admin panel.")
    .RequireAuthorization("AdminOnly");

// User-only endpoint
app.MapGet("/secure/user-profile", () => "This is the user profile.")
    .RequireAuthorization("UserOnly");

app.Run();
