using System;

namespace IdentityAuth.Models.Users;

public class InfoResponseModel
{
    public string Id { get; set; }
    public string Email { get; set; }
    public bool IsEmailConfirmed { get; set; }
}
