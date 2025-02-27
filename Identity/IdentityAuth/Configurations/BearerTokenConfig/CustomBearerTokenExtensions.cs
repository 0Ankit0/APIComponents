// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using IdentityAuth.Configurations;
using IdentityAuth.Models.Users;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.BearerToken;
using Microsoft.AspNetCore.Http.Json;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Extension methods to configure the bearer token authentication.
/// </summary>
public static class BearerTokenExtensions
{
    /// <summary>
    /// Adds bearer token authentication. The default scheme is specified by <see cref="BearerTokenDefaults.AuthenticationScheme"/>.
    /// <para>
    /// Bearer tokens can be obtained by calling <see cref="AuthenticationHttpContextExtensions.SignInAsync(AspNetCore.Http.HttpContext, string?, System.Security.Claims.ClaimsPrincipal)" />.
    /// </para>
    /// </summary>
    /// <param name="builder">The <see cref="AuthenticationBuilder"/>.</param>
    /// <returns>A reference to <paramref name="builder"/> after the operation has completed.</returns>
    public static AuthenticationBuilder AddCustomBearerToken(this AuthenticationBuilder builder)
        => builder.AddCustomBearerToken(BearerTokenDefaults.AuthenticationScheme);

    /// <summary>
    /// Adds bearer token authentication.
    /// <para>
    /// Bearer tokens can be obtained by calling <see cref="AuthenticationHttpContextExtensions.SignInAsync(AspNetCore.Http.HttpContext, string?, System.Security.Claims.ClaimsPrincipal)" />.
    /// </para>
    /// </summary>
    /// <param name="builder">The <see cref="AuthenticationBuilder"/>.</param>
    /// <param name="authenticationScheme">The authentication scheme.</param>
    /// <returns>A reference to <paramref name="builder"/> after the operation has completed.</returns>
    public static AuthenticationBuilder AddCustomBearerToken(this AuthenticationBuilder builder, string authenticationScheme)
        => builder.AddCustomBearerToken(authenticationScheme, _ => { });

    /// <summary>
    /// Adds bearer token authentication. The default scheme is specified by <see cref="BearerTokenDefaults.AuthenticationScheme"/>.
    /// <para>
    /// Bearer tokens can be obtained by calling <see cref="AuthenticationHttpContextExtensions.SignInAsync(AspNetCore.Http.HttpContext, string?, System.Security.Claims.ClaimsPrincipal)" />.
    /// </para>
    /// </summary>
    /// <param name="builder">The <see cref="AuthenticationBuilder"/>.</param>
    /// <param name="configure">Action used to configure the bearer token authentication options.</param>
    /// <returns>A reference to <paramref name="builder"/> after the operation has completed.</returns>
    public static AuthenticationBuilder AddCustomBearerToken(this AuthenticationBuilder builder, Action<BearerTokenOptions> configure)
        => builder.AddCustomBearerToken(BearerTokenDefaults.AuthenticationScheme, configure);

    /// <summary>
    /// Adds bearer token authentication.
    /// <para>
    /// Bearer tokens can be obtained by calling <see cref="AuthenticationHttpContextExtensions.SignInAsync(AspNetCore.Http.HttpContext, string?, System.Security.Claims.ClaimsPrincipal)" />.
    /// </para>
    /// </summary>
    /// <param name="builder">The <see cref="AuthenticationBuilder"/>.</param>
    /// <param name="authenticationScheme">The authentication scheme.</param>
    /// <param name="configure">Action used to configure the bearer token authentication options.</param>
    /// <returns>A reference to <paramref name="builder"/> after the operation has completed.</returns>
    public static AuthenticationBuilder AddCustomBearerToken(this AuthenticationBuilder builder, string authenticationScheme, Action<BearerTokenOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(authenticationScheme);
        ArgumentNullException.ThrowIfNull(configure);

        builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<IConfigureOptions<BearerTokenOptions>, CustomBearerTokenConfigureOptions>());
        return builder.AddScheme<BearerTokenOptions, CustomBearerTokenHandler>(authenticationScheme, configure);
    }
}
