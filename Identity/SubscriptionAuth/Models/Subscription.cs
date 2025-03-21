namespace SubscriptionAuth.Models
{
    public class Subscription
    {
        public int Id { get; set; }
        public string? UserId { get; set; }
        public DateTime StartDate { get; set; }
        public DateTime EndDate { get; set; }
        public string? Level { get; set; }
        public bool IsActive => EndDate > DateTime.UtcNow;
    }
}