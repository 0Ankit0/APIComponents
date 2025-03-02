using System;
using FluentValidation;
using IdentityAuth.Models.Users;

namespace IdentityAuth.Validators;

public class RoleModelValidator : AbstractValidator<RoleModel>
{
    public RoleModelValidator()
    {
        RuleFor(x => x.Name).NotEmpty().WithMessage("Role name is required.");
    }

}
