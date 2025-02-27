using System;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.BearerToken;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Options;

namespace IdentityAuth.Models.Users;

internal sealed class CustomBearerTokenConfigureOptions(IDataProtectionProvider dp) : IConfigureNamedOptions<BearerTokenOptions>
{
    private const string _primaryPurpose = "Microsoft.AspNetCore.Authentication.BearerToken";

    public void Configure(string? schemeName, BearerTokenOptions options)
    {
        if (schemeName is null)
        {
            return;
        }

        options.BearerTokenProtector = new TicketDataFormat(dp.CreateProtector(_primaryPurpose, schemeName, "BearerToken"));
        options.RefreshTokenProtector = new TicketDataFormat(dp.CreateProtector(_primaryPurpose, schemeName, "RefreshToken"));
    }

    public void Configure(BearerTokenOptions options)
    {
        throw new NotImplementedException();
    }
}

