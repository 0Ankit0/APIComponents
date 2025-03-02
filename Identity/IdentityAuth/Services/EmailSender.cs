using System;
using IdentityAuth.Data;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;

namespace IdentityAuth.Services;

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
// public class EmailSender2 : IEmailSender
// {
//     public Task SendEmailAsync(string email, string subject, string htmlMessage)
//     {
//         // Log the email to the console (or implement actual email sending logic)
//         Console.WriteLine($"Sending email to {email} with subject {subject}");
//         Console.WriteLine(htmlMessage);
//         return Task.CompletedTask;
//     }

// }
