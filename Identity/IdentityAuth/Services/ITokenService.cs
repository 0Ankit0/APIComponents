using System;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.BearerToken;

namespace IdentityAuth.Services;
public interface ITokenService
{
    string GenerateAccessToken(ClaimsPrincipal user);
    AccessTokenResponse GenerateTokens(ClaimsPrincipal user);
    string GenerateRefreshToken(ClaimsPrincipal user);
    AuthenticationTicket? ValidateToken(string token);
}

