using System;
using Microsoft.AspNetCore.Http.Json;
using Microsoft.Extensions.Options;

namespace IdentityAuth.Configurations.BearerTokenConfig;

internal sealed class CustomBearerTokenConfigureJsonOptions : IConfigureOptions<JsonOptions>
{
    public void Configure(JsonOptions options)
    {
        // Put our resolver in front of the reflection-based one. See ProblemDetailsOptionsSetup for a detailed explanation.
        options.SerializerOptions.TypeInfoResolverChain.Insert(0, BearerTokenJsonSerializerContext.Default);
    }
}
