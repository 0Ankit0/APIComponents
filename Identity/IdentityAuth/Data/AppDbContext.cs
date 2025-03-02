using IdentityAuth.Models;
using IdentityAuth.Models.Users;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace IdentityAuth.Data
{

    public class AppDbContext : IdentityDbContext<Users, Roles, string>
    {
        public AppDbContext(DbContextOptions<AppDbContext> options)
             : base(options) { }
    }
}
