using System;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Authentication.BearerToken;

namespace IdentityAuth.Models.Users;

[JsonSerializable(typeof(AccessTokenResponse))]
public partial class CustomBearerTokenJsonSerializerContext : JsonSerializerContext
{
}
