using System;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.BearerToken;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Options;

namespace IdentityAuth.Services
{
    public class TokenService : ITokenService
    {
        private readonly IDataProtector _tokenProtector;
        private readonly BearerTokenOptions _options;

        public TokenService(IDataProtectionProvider dataProtectionProvider, IOptions<BearerTokenOptions> options)
        {
            _tokenProtector = dataProtectionProvider.CreateProtector("BearerToken");
            _options = options.Value;
        }

        public AccessTokenResponse GenerateTokens(ClaimsPrincipal user)
        {
            // Generate the access token and refresh token
            var accessToken = GenerateAccessToken(user);
            var refreshToken = GenerateRefreshToken(user);

            // Build and return the AccessTokenResponse
            var response = new AccessTokenResponse
            {
                AccessToken = accessToken,
                ExpiresIn = (long)_options.BearerTokenExpiration.TotalSeconds,
                RefreshToken = refreshToken
            };

            return response;
        }

        public string GenerateAccessToken(ClaimsPrincipal user)
        {
            var utcNow = DateTimeOffset.UtcNow;
            var authProperties = new AuthenticationProperties
            {
                ExpiresUtc = utcNow + _options.BearerTokenExpiration
            };

            var ticket = new AuthenticationTicket(user, authProperties, "Bearer:AccessToken");
            var serializedTicket = Convert.ToBase64String(TicketSerializer.Default.Serialize(ticket));
            return _tokenProtector.Protect(serializedTicket);
        }

        public string GenerateRefreshToken(ClaimsPrincipal user)
        {
            var utcNow = DateTimeOffset.UtcNow;
            var refreshProperties = new AuthenticationProperties
            {
                ExpiresUtc = utcNow + _options.RefreshTokenExpiration
            };

            var ticket = new AuthenticationTicket(user, refreshProperties, "Bearer:RefreshToken");
            var serializedTicket = Convert.ToBase64String(TicketSerializer.Default.Serialize(ticket));
            return _tokenProtector.Protect(serializedTicket);
        }

        public AuthenticationTicket? ValidateToken(string token)
        {
            try
            {
                var unprotectedData = _tokenProtector.Unprotect(token);
                return TicketSerializer.Default.Deserialize(Convert.FromBase64String(unprotectedData));
            }
            catch
            {
                return null;
            }
        }
    }
}
