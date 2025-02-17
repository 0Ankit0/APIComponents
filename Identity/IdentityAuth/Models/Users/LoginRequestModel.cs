using System;

namespace IdentityAuth.Models.Users;

public class LoginRequestModel
{
    public string Email { get; set; }
    public string Password { get; set; }
    public bool RememberMe { get; set; }
    public string TwoFactorCode { get; set; }
    public string TwoFactorRecoveryCode { get; set; }
}
