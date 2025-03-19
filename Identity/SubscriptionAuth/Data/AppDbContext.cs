using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using SubscriptionAuth.Models;

namespace SubscriptionAuth.Data
{
    public class AppDbContext : IdentityDbContext<Users, Roles, string>
    {
        public DbSet<Subscription> Subscriptions { get; set; }

        public AppDbContext(DbContextOptions<AppDbContext> options)
             : base(options) { }
    }
}
