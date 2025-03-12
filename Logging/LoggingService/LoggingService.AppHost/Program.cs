var builder = DistributedApplication.CreateBuilder(args);

var apiProject = builder.AddProject<Projects.LoggingApi>("api")
                    .WithExternalHttpEndpoints();
                    

builder.Build().Run();
