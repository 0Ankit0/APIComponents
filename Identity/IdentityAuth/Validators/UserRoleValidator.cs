using System;
using FluentValidation;
using IdentityAuth.Models.Users;

namespace IdentityAuth.Validators;

public class UserRoleValidator : AbstractValidator<UserRoleModel>
{
    public UserRoleValidator()
    {
        RuleFor(x => x.Name).NotEmpty().WithMessage("Role name is required.");
    }

}
