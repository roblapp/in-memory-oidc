namespace Authentication.Server.IdentityServer
{
    using System.Collections.Generic;
    using Authentication.Server.Dtos;
    using IdentityServer4;
    using IdentityServer4.Models;

    public class InMemoryResources
    {
        // scopes define the resources in your system
        public static List<IdentityResource> GetIdentityResources()
        {
            //Model a User
            return new List<IdentityResource>
                   {
                       new IdentityResources.OpenId(),
                       new IdentityResources.Profile()
                       //new IdentityResource(name: "IDResourceName", claimTypes: new List<string> {"IDRClaimType1", "IDRClaimType2"}),
                       //new IdentityResource
                       //{
                       //    DisplayName = "",
                       //    Description = "",
                       //    Enabled = true,
                       //    Name = "",
                       //    ShowInDiscoveryDocument = true,
                       //    Emphasize = true,
                       //    Required = true,
                       //    UserClaims = new List<string>
                       //                 {
                       //                     ""
                       //                 }
                       //}
                   };
        }

        public static List<ApiResource> GetApiResources()
        {
            return new List<ApiResource>
                   {
                       //When you call this constructor (any constructor with a 'string name' parameter, the constructor will
                       //automatically create a new Scope(name, ...) and add it to it's Scopes property. Directly from the
                       //IdentityServer4 documentation: An API must have at least one scope. Each scope can have different settings
                       //See here https://identityserver4.readthedocs.io/en/release/reference/api_resource.html
                       new ApiResource
                       {
                           DisplayName = "Test API Resource (For Test API)",
                           Description = "This resource represents a test API",
                           Enabled = true,
                           Name = "api.resource",
                           Scopes = new List<Scope>
                                    {
                                        new Scope
                                        {
                                            Name = "api.resource.read",
                                            DisplayName = "Read Api Scope",
                                            Description = "A scope for reading from the test API",
                                            //Claims required for reading from the API
                                            UserClaims = new List<string>
                                                         {
                                                             "name"
                                                         }
                                        },

                                        new Scope
                                        {
                                            Name = "api.resource.write",
                                            DisplayName = "Write Api Scope",
                                            Description = "A scope for writing to the test API",
                                            //Claims required for writing to the API
                                            UserClaims = new List<string>
                                                         {
                                                             "name",
                                                             "role",
                                                             "email"
                                                         }
                                        }
                                    },
                           UserClaims = new List<string>()
                       }
                   };
        }

        public static List<Client> GetClients()
        {
            return new List<Client>
                   {
                       // JavaScript Client (Open Id Connect)
                       new Client
                       {
                           ClientId = "js-client-id",
                           ClientName = "JavaScript Client",
                           AllowedGrantTypes = GrantTypes.Implicit,
                           AllowAccessTokensViaBrowser = true,
                           AlwaysSendClientClaims = true,
                           RequireConsent = false,

                           AlwaysIncludeUserClaimsInIdToken = true,

                           RedirectUris =           { "http://localhost:5002/index.html", "http://localhost:5002/callback.html", "http://localhost:5002/silent.html" },
                           PostLogoutRedirectUris = { "http://localhost:5002/index.html" },
                           AllowedCorsOrigins =     { "http://localhost:5002" },

                           AllowedScopes =
                           {
                               IdentityServerConstants.StandardScopes.OpenId,
                               IdentityServerConstants.StandardScopes.Profile,
                               "api.resource.read",
                               "api.resource.write"
                           }
                       },

                       // Native client
                       new Client
                       {
                           ClientId = "native-client-id",
                           ClientName = "Native Client",
                           AllowedGrantTypes = GrantTypes.CodeAndClientCredentials,
                           AllowAccessTokensViaBrowser = true,
                           AlwaysSendClientClaims = true,
                           RequireConsent = false,

                           AlwaysIncludeUserClaimsInIdToken = true,

                           RedirectUris =           { "http://native.app" },
                           PostLogoutRedirectUris = { "http://native.app" },
                           AllowedCorsOrigins =     { "http://native.app" },

                           AllowedScopes =
                           {
                               IdentityServerConstants.StandardScopes.OpenId,
                               IdentityServerConstants.StandardScopes.Profile,
                               "api.resource.read",
                               "api.resource.write"
                           }

                           //ClientSecrets = new List<Secret>
                           //                {
                           //                    new Secret
                           //                    {
                           //                        Type = "",
                           //                        Value = "",
                           //                        Description = ""
                           //                    }
                           //                }
                       },

                       // Custom Grant Client
                       new Client
                       {
                           ClientId = "jwt-bearer-grant-client",
                           ClientName = "Native Client",
                           AllowedGrantTypes = new[] { "urn:ietf:params:oauth:grant-type:jwt-bearer" },
                           AllowAccessTokensViaBrowser = true,
                           AlwaysSendClientClaims = true,
                           RequireConsent = false,
                           RequireClientSecret = false,

                           AlwaysIncludeUserClaimsInIdToken = true,

                           RedirectUris =           { "http://native.app" },
                           PostLogoutRedirectUris = { "http://native.app" },
                           AllowedCorsOrigins =     { "http://native.app" },

                           AllowedScopes =
                           {
                               IdentityServerConstants.StandardScopes.OpenId,
                               IdentityServerConstants.StandardScopes.Profile,
                               "api.resource.read",
                               "api.resource.write"
                           }

                           //ClientSecrets = new List<Secret>
                           //                {
                           //                    new Secret
                           //                    {
                           //                        Type = "",
                           //                        Value = "",
                           //                        Description = ""
                           //                    }
                           //                }
                       }
                   };
        }

        public static List<UserDto> GetUsers()
        {
            return new List<UserDto>
                   {
                       new UserDto
                       {
                           Username = "x",
                           Password = "x",
                           IsActive = true,
                           UserId = "fb4a6d23-e383-4b64-95f5-5b62601ac9cb",
                           Email = "x@x.com",
                           ProviderName = "Local"
                       },

                       new UserDto
                       {
                           Username = "lapp.robert@yahoo.com",
                           IsActive = true,
                           UserId = "425b7fba-1bf1-4368-b499-178860fb75f3",
                           Email = "lapp.robert@yahoo.com",
                           ProviderName = "Google",
                           ProviderSubjectId = "104363021797538463603"
                       }
                   };
        }
    }
}
