using FluentValidation;
using FluentValidation.AspNetCore;
using IdentityAuth.Configurations;
using IdentityAuth.Data;
using IdentityAuth.Models;
using IdentityAuth.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.OpenApi.Models;
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
builder.Services.AddAuthentication()
    .AddCustomBearerToken(IdentityConstants.BearerScheme, options =>
    {
        options.BearerTokenExpiration = TimeSpan.FromMinutes(30); // Set token expiration
        options.RefreshTokenExpiration = TimeSpan.FromDays(7); // Set refresh token expiration
    });

builder.Services.AddAuthorization();
builder.Services.AddDbContext<AppDbContext>(x => x.UseSqlite(connectionString));

//if you don't require role use AddDefaultIdentity<userModel>() else use AddIdentity<userModel,roleModel>()
//the adddefaulttokenproviders is used to generate token automatically in the login process
builder.Services.AddIdentity<User, IdentityRole>()
    .AddEntityFrameworkStores<AppDbContext>()
    .AddDefaultTokenProviders();


builder.Services.AddTransient<IEmailSender<User>, EmailSender1>();
builder.Services.AddTransient<IEmailSender, EmailSender2>();

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

// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(options =>
{
    options
    .AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        In = ParameterLocation.Header,
        Description = "Please enter Bearer token",
        Name = "Authorization",
        Type = SecuritySchemeType.Http,
        BearerFormat = "IdentityAuth",
        Scheme = "bearer"
    });
    options
    .AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "Bearer"
                }
            },
            new string[] { }
        }
    });
});
var app = builder.Build();

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
