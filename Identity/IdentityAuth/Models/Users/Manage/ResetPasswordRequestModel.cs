using System;

namespace IdentityAuth.Models.Users;

public class ResetPasswordRequestModel
{
    public string Email { get; set; }
    public string ResetCode { get; set; }
    public string NewPassword { get; set; }

}
