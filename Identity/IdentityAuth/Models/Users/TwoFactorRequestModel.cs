using System;

namespace IdentityAuth.Models.Users;

public class TwoFactorRequestModel
{
    public bool Enable { get; set; }
    public bool ResetSharedKey { get; set; }
    public string TwoFactorCode { get; set; }
    public bool ResetRecoveryCodes { get; set; }
    public bool ForgetMachine { get; set; }
}
