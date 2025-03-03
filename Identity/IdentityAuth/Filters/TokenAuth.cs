using System;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;

namespace IdentityAuth.Filters;

[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, Inherited = true, AllowMultiple = true)]
public class TokenAuth : AuthorizeAttribute, IAuthorizationFilter
{
    public TokenAuth()
    {
        AuthenticationSchemes = $"{IdentityConstants.BearerScheme},{IdentityConstants.ApplicationScheme}";
    }

    public void OnAuthorization(AuthorizationFilterContext context)
    {
        // Retrieve the user principal from the current HttpContext.
        var user = context.HttpContext.User;

        // If the user is not authenticated, return an Unauthorized result.
        if (user == null || !user.Identity.IsAuthenticated)
        {
            context.Result = new UnauthorizedResult();
            return;
        }

        // If Roles are specified, check if the user belongs to any of the required roles.
        if (!string.IsNullOrEmpty(Roles))
        {
            var roles = Roles.Split(',')
                             .Select(r => r.Trim())
                             .Where(r => !string.IsNullOrEmpty(r));

            bool inRole = roles.Any(role => user.IsInRole(role));
            if (!inRole)
            {
                context.Result = new ForbidResult();
                return;
            }
        }

        // If a Policy is specified, perform a custom check.
        // For demonstration purposes, assume that the user must have a claim "Policy" matching the provided value.
        if (!string.IsNullOrEmpty(Policy))
        {
            var hasPolicyClaim = user.HasClaim(c => c.Type == "Policy" && c.Value.Equals(Policy, StringComparison.OrdinalIgnoreCase));
            if (!hasPolicyClaim)
            {
                context.Result = new ForbidResult();
                return;
            }
        }

        // Additional custom checks can be added here if needed.
    }
}