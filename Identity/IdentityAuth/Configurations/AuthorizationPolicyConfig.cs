using IdentityAuth.Models.Users;
using Microsoft.AspNetCore.Identity;

namespace IdentityAuth.Configurations
{
    public static class AuthorizationPolicyConfig
    {
        public static void ConfigurePolicies(IServiceCollection services)
        {
            services.AddAuthorization(options =>
            {
                options.AddPolicy("RequireAdminRole", policy => policy.RequireRole("Admin"));
                options.AddPolicy("RequireUserRole", policy => policy.RequireRole("User"));
                options.AddPolicy("RequireAdminOrUserRole", policy => policy.RequireRole("Admin", "User"));
            });
        }

        public static async Task EnsureRolesExistAsync(IServiceProvider serviceProvider)
        {
            using (var scope = serviceProvider.CreateScope())
            {
                var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<Roles>>();

                string[] roles = { "Admin", "User" };

                foreach (var role in roles)
                {
                    if (!await roleManager.RoleExistsAsync(role))
                    {
                        await roleManager.CreateAsync(new Roles(role));
                    }
                }
            }
        }
    }
}
