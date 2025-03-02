using System;
using FluentValidation;
using IdentityAuth.Models.Users;

namespace IdentityAuth.Validators;

public class UserRoleModelValidator : AbstractValidator<UserRoleModel>
{
    public UserRoleModelValidator()
    {
        RuleFor(x => x.UserId).NotEmpty().NotNull().WithMessage("UserId is required.");
        RuleFor(x => x.RoleName).NotEmpty().NotNull().WithMessage("RoleName is required.");
    }
}
