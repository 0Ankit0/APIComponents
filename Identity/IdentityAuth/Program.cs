using FluentValidation;
using FluentValidation.AspNetCore;
using IdentityAuth.Configurations;
using IdentityAuth.Data;
using IdentityAuth.Models.Users;
using IdentityAuth.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using System.Reflection;
using System.Text.Json;
using System.Text.Json.Serialization;

var builder = WebApplication.CreateBuilder(args);
var connectionString = builder.Configuration.GetConnectionString("AppDbContextConnection") ?? throw new InvalidOperationException("Connection string 'AppDbContextConnection' not found."); ;

//Register the TokenService as a singleton
builder.Services.AddSingleton<ITokenService, TokenService>();

// Add services to the container.
// builder.Services.AddAuthentication().AddBearerToken(IdentityConstants.BearerScheme);
// builder.Services.AddAuthorizationBuilder();

//added custom bearer token scheme
builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = IdentityConstants.BearerScheme;
    options.DefaultChallengeScheme = IdentityConstants.BearerScheme;
    options.DefaultScheme = IdentityConstants.BearerScheme;
})
    .AddCustomBearerToken(IdentityConstants.BearerScheme, options =>
    {
        options.BearerTokenExpiration = TimeSpan.FromMinutes(30); // Set token expiration
        options.RefreshTokenExpiration = TimeSpan.FromDays(7); // Set refresh token expiration
    });

AuthorizationPolicyConfig.ConfigurePolicies(builder.Services);

builder.Services.AddDbContext<AppDbContext>(x => x.UseSqlite(connectionString));

//if you don't require role use AddDefaultIdentity<userModel>() else use AddIdentity<userModel,roleModel<IdType>>()
//the adddefaulttokenproviders is used to generate token automatically in the login process
builder.Services.AddIdentity<Users, Roles>()
    .AddEntityFrameworkStores<AppDbContext>()
    .AddDefaultTokenProviders();


builder.Services.AddTransient<IEmailSender<Users>, EmailSender>();
// builder.Services.AddTransient<IEmailSender, EmailSender2>();

builder.Services.AddControllers()
 .AddJsonOptions(options =>
            {
                // Add custom serialization settings here if needed
                options.JsonSerializerOptions.PropertyNamingPolicy = JsonNamingPolicy.CamelCase;
                options.JsonSerializerOptions.Converters.Add(new JsonStringEnumConverter());
            });

builder.Services.AddFluentValidationAutoValidation() // Enables automatic validation
                .AddFluentValidationClientsideAdapters(); // Enables client-side validation for MVC

builder.Services.AddValidatorsFromAssembly(Assembly.GetExecutingAssembly()); // Scans & registers all validators

var swaggerConfig = new SwaggerConfig(builder.Configuration);
swaggerConfig.ConfigureServices(builder.Services);

var app = builder.Build();
// Ensure roles exist before handling requests
using (var scope = app.Services.CreateScope())
{
    var services = scope.ServiceProvider;
    await AuthorizationPolicyConfig.EnsureRolesExistAsync(services);
}

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();


app.UseAuthentication();
app.UseAuthorization();

// app.MapIdentityApi<User>();

app.MapControllers();

app.Run();
