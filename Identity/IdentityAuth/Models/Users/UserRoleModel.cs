using System;
using Microsoft.AspNetCore.Identity;

namespace IdentityAuth.Models.Users;

public class UserRoleModel : IdentityRole
{
    public string? UserId { get; set; }
    public string? RoleName { get; set; }


}
