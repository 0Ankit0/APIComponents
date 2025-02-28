using IdentityAuth.Configurations.BearerTokenConfig;
using IdentityAuth.Models.Users;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.BearerToken;
using Microsoft.AspNetCore.Http.Json;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace IdentityAuth.Configurations;

/// <summary>
/// Extension methods to configure the bearer token authentication.
/// </summary>
public static class CustomBearerTokenExtensions
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


        builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<IConfigureOptions<JsonOptions>, CustomBearerTokenConfigureJsonOptions>());
        builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<IConfigureOptions<BearerTokenOptions>, CustomBearerTokenConfigureOptions>());
        return builder.AddScheme<BearerTokenOptions, CustomBearerTokenHandler>(authenticationScheme, configure);
    }
}
