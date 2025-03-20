using Microsoft.AspNetCore.Authorization;
using System.Collections.Generic;

namespace SubscriptionAuth.Infrastructure;
public class SubscriptionRequirement : IAuthorizationRequirement
{
    public List<string> ValidLevels { get; }

    public SubscriptionRequirement(List<string> validLevels)
    {
        ValidLevels = validLevels;
    }
}