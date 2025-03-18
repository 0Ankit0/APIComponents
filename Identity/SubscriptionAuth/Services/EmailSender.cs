using Microsoft.AspNetCore.Identity;
using SubscriptionAuth.Data;

namespace SubscriptionAuth.Services
{
    public class EmailSender : IEmailSender<Users>
    {
        public Task SendConfirmationLinkAsync(Users user, string email, string confirmationLink)
        {
            Console.WriteLine($"Sending confirmation link to {email} with link {confirmationLink}");
            return Task.CompletedTask;
        }
        public Task SendPasswordResetLinkAsync(Users user, string email, string resetLink)
        {
            Console.WriteLine($"Sending password reset link to {email} with link {resetLink}");
            return Task.CompletedTask;
        }
        public Task SendPasswordResetCodeAsync(Users user, string email, string resetCode)
        {
            Console.WriteLine($"Sending password reset code to {email} with code {resetCode}");
            return Task.CompletedTask;
        }
    }
}
