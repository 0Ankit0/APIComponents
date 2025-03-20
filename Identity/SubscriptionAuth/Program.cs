using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using SubscriptionAuth.Data;
using SubscriptionAuth.Infrastructure;
using SubscriptionAuth.Services;

var builder = WebApplication.CreateBuilder(args);

var connectionString = builder.Configuration.GetConnectionString("AppDbContextConnection") ?? throw new InvalidOperationException("Connection string 'AppDbContextConnection' not found."); ;

// Add services to the container.
builder.Services.AddAuthentication().AddBearerToken(IdentityConstants.BearerScheme);
builder.Services.AddAuthorizationBuilder();

builder.Services.AddIdentity<Users, Roles>()
    .AddEntityFrameworkStores<AppDbContext>()
    .AddDefaultTokenProviders();

builder.Services.AddTransient<IEmailSender<Users>, EmailSender>();

builder.Services.AddControllers();
// Learn more about configuring OpenAPI at https://aka.ms/aspnet/openapi
builder.Services.AddOpenApi();

builder.Services.AddScoped<SubscriptionService>();

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("BasicSubscription", policy =>
        policy.Requirements.Add(new SubscriptionRequirement(new List<string> { "Basic", "Premium", "VIP" })));
    options.AddPolicy("PremiumSubscription", policy =>
        policy.Requirements.Add(new SubscriptionRequirement(new List<string> { "Premium", "VIP" })));
    options.AddPolicy("VIPSubscription", policy =>
        policy.Requirements.Add(new SubscriptionRequirement(new List<string> { "VIP" })));
});

builder.Services.AddSingleton<IAuthorizationHandler, SubscriptionHandler>();
var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}

app.UseHttpsRedirection();

app.UseAuthorization();

app.MapControllers();

app.Run();
