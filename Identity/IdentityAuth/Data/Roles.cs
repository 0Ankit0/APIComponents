using System;
using Microsoft.AspNetCore.Identity;

namespace IdentityAuth.Models.Users;

public class Roles : IdentityRole
{
    public Roles() : base() { }

    public Roles(string roleName) : base(roleName) { }
}
