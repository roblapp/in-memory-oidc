namespace Authentication.Server.Extensions
{
    using Authentication.Server.IdentityServer;
    using Microsoft.Extensions.DependencyInjection;

    public static class IdentityServerExtensions
    {
        public static IIdentityServerBuilder Configure(this IIdentityServerBuilder identityServerBuilder)
        {
            identityServerBuilder
                .AddDeveloperSigningCredential()
                //.AddProfileService<>(),
                .AddInMemoryIdentityResources(InMemoryResources.GetIdentityResources())
                .AddInMemoryApiResources(InMemoryResources.GetApiResources())
                .AddInMemoryClients(InMemoryResources.GetClients())
                .AddExtensionGrantValidator<RFC7523GrantValidator>();

            return identityServerBuilder;
        }
    }
}
