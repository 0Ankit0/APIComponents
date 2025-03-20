using Microsoft.AspNetCore.Authorization;
using SubscriptionAuth.Services;
using System.Threading.Tasks;

namespace SubscriptionAuth.Infrastructure;
public class SubscriptionHandler : AuthorizationHandler<SubscriptionRequirement>
{
    private readonly SubscriptionService _subscriptionService;

    public SubscriptionHandler(SubscriptionService subscriptionService)
    {
        _subscriptionService = subscriptionService;
    }

    protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, SubscriptionRequirement requirement)
    {
        var userId = context.User.Identity?.Name;
        if (userId != null)
        {
            var subscription = _subscriptionService.GetSubscription(userId);
            if (subscription != null && subscription.IsActive && requirement.ValidLevels.Contains(subscription.Level))
            {
                context.Succeed(requirement);
            }
            else
            {
                context.Fail();
            }
        }
        else
        {
            context.Fail();
        }

        return Task.CompletedTask;
    }
}