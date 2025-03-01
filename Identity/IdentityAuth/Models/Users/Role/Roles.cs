using System;
using Microsoft.AspNetCore.Identity;

namespace IdentityAuth.Models.Users;
public class Roles : Roles<string>
{
    /// <summary>
    /// Initializes a new instance of <see cref="Roles"/>.
    /// </summary>
    /// <remarks>
    /// The Id property is initialized to form a new GUID string value.
    /// </remarks>
    public Roles()
    {
        Id = Guid.NewGuid().ToString();
    }

    /// <summary>
    /// Initializes a new instance of <see cref="Roles"/>.
    /// </summary>
    /// <param name="roleName">The role name.</param>
    /// <remarks>
    /// The Id property is initialized to form a new GUID string value.
    /// </remarks>
    public Roles(string roleName) : this()
    {
        Name = roleName;
    }
}

public class Roles<TKey> where TKey : IEquatable<TKey>
{
    /// <summary>
    /// Initializes a new instance of <see cref="Roles{TKey}"/>.
    /// </summary>
    public Roles() { }

    /// <summary>
    /// Initializes a new instance of <see cref="Roles{TKey}"/>.
    /// </summary>
    /// <param name="roleName">The role name.</param>
    public Roles(string roleName) : this()
    {
        Name = roleName;
    }

    /// <summary>
    /// Gets or sets the primary key for this role.
    /// </summary>
    public virtual TKey Id { get; set; } = default!;

    /// <summary>
    /// Gets or sets the name for this role.
    /// </summary>
    public virtual string? Name { get; set; }

    /// <summary>
    /// Gets or sets the normalized name for this role.
    /// </summary>
    public virtual string? NormalizedName { get; set; }

    /// <summary>
    /// A random value that should change whenever a role is persisted to the store
    /// </summary>
    public virtual string? ConcurrencyStamp { get; set; }

    /// <summary>
    /// Returns the name of the role.
    /// </summary>
    /// <returns>The name of the role.</returns>
    public override string ToString()
    {
        return Name ?? string.Empty;
    }
}

