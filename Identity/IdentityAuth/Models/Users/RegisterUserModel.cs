using System;

namespace IdentityAuth.Models.Users;

public class RegisterUserModel
{
    public string Email { get; set; }
    public string Password { get; set; }
    public string ConfirmPassword { get; set; }
}
