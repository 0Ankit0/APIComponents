using System;

namespace IdentityAuth.Models.Users;

public class TwoFactorResponseModel
{
    public string SharedKey { get; set; }
    public string[] RecoveryCodes { get; set; }
    public int RecoveryCodesLeft { get; set; }
    public bool IsTwoFactorEnabled { get; set; }
    public bool IsMachineRemembered { get; set; }
}
