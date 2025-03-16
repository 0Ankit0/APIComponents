using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace SubscriptionAuth.Data
{
    public class AppDbContext : IdentityDbContext<Users, Roles, string>
    {
        public AppDbContext(DbContextOptions<AppDbContext> options)
             : base(options) { }
    }
}
