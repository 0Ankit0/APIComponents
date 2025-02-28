using System;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Authentication.BearerToken;

namespace IdentityAuth.Configurations.BearerTokenConfig;

[JsonSerializable(typeof(AccessTokenResponse))]
internal sealed partial class BearerTokenJsonSerializerContext : JsonSerializerContext
{
}
