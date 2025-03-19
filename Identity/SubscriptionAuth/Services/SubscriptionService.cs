using SubscriptionAuth.Data;
using SubscriptionAuth.Models;
using System.Linq;

namespace SubscriptionAuth.Services
{
    public class SubscriptionService
    {
        private readonly AppDbContext _context;

        public SubscriptionService(AppDbContext context)
        {
            _context = context;
        }

        public Subscription GetSubscription(string userId)
        {
            return _context.Subscriptions.FirstOrDefault(s => s.UserId == userId);
        }
    }
}