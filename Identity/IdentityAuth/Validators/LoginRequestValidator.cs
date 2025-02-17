using System;
using FluentValidation;
using IdentityAuth.Models.Users;

namespace IdentityAuth.Validators;

public class LoginRequestValidator : AbstractValidator<LoginRequestModel>
{
    public LoginRequestValidator()
    {
        RuleFor(x => x.Email)
            .NotEmpty().WithMessage("Email is required.")
            .EmailAddress().WithMessage("Invalid email format.");

        RuleFor(x => x.Password)
            .NotEmpty().WithMessage("Password is required");
    }
}
