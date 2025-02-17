using System;

namespace IdentityAuth.Models.Users;

public class InfoRequestModel
{
    public string NewEmail { get; set; }
    public string OldPassword { get; set; }
    public string NewPassword { get; set; }
}
