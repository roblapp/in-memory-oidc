namespace Authentication.Server.Services.Login
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Security.Authentication;
    using System.Security.Claims;
    using System.Threading.Tasks;
    using Authentication.Server.Dtos;
    using Authentication.Server.Extensions;
    using Authentication.Server.Services.Users;
    using IdentityModel;
    using IdentityServer4;
    using IdentityServer4.Events;
    using IdentityServer4.Services;
    using Microsoft.AspNetCore.Authentication;
    using Microsoft.AspNetCore.Http;
    using Microsoft.Extensions.Logging;

    public interface IExternalLoginService : IBaseService
    {
        Task DoExternalLoginCallbackProcessAsync(HttpContext httpContext);
    }

    public class ExternalLoginService : BaseService, IExternalLoginService
    {
        private readonly IEventService eventsService;
        private readonly IUserService userService;

        public ExternalLoginService(ILogger<ExternalLoginService> logger, IEventService eventsService, IUserService userService)
            : base(logger)
        {
            this.eventsService = eventsService;
            this.userService = userService;
        }

        public async Task DoExternalLoginCallbackProcessAsync(HttpContext httpContext)
        {
            try
            {
                // read external identity from the temporary cookie
                var authenticationResult = await httpContext.AuthenticateAsync(IdentityServerConstants.ExternalCookieAuthenticationScheme);

                if (authenticationResult?.Succeeded != true)
                {
                    throw new AuthenticationException("User was not authenticated successfully by the external provider");
                }

                var externalUser = authenticationResult.Principal;
                var externalUserClaims = externalUser.Claims.ToList();

                var providerIdentifierClaim = externalUserClaims.GetProviderIdClaim();
                var providerIdentifier = providerIdentifierClaim.Value;

                // remove the user id claim from the claims collection and move to the userId property
                externalUserClaims.Remove(providerIdentifierClaim);

                var provider = authenticationResult.Properties.Items["scheme"];
                var user = await this.userService.GetSingleOrDefaultAsync(x => x.IsActive && x.ProviderName == provider && x.ProviderSubjectId == providerIdentifier);

                if (user == null)
                {
                    this.Logger.LogDebug("User {providerIdentifier} was not found in the user store, adding user on the fly", providerIdentifier);
                    user = new UserDto
                           {
                               UserId = Guid.NewGuid().ToString(),
                               Username = providerIdentifier,
                               ProviderSubjectId = providerIdentifier,
                               IsActive = true,
                               ProviderName = provider
                           };
                    await this.userService.CreateAsync(user);
                }

                //Add sessionId claim to the list of additional claims
                var additionalClaims = new List<Claim>();
                var sessionIdClaim = externalUserClaims.FirstOrDefault(x => x.Type == JwtClaimTypes.SessionId);
                if (sessionIdClaim != null)
                {
                    // if the external system sent a session id claim, copy it over
                    additionalClaims.Add(new Claim(JwtClaimTypes.SessionId, sessionIdClaim.Value));
                }

                var externalOidcIdToken = authenticationResult.Properties.GetTokenValue("id_token"); // if the external provider issued an id_token, we'll keep it for signout
                AuthenticationProperties props = null;
                if (externalOidcIdToken != null)
                {
                    props = new AuthenticationProperties();
                    props.StoreTokens(
                        new[]
                        {
                            new AuthenticationToken
                            {
                                Name = "id_token",
                                Value = externalOidcIdToken
                            }
                        });
                }

                // issue authentication cookie for user
                await this.eventsService.RaiseAsync(new UserLoginSuccessEvent(provider, user.ProviderSubjectId, user.UserId, user.Username));

                await httpContext.SignInAsync(user.UserId, user.Username, provider, props, additionalClaims.ToArray());
            }
            catch (Exception exception)
            {
                this.Logger.LogDebug(exception.Message);
                throw;
            }
            finally
            {
                // delete temporary cookie used during external authentication
                await httpContext.SignOutAsync(IdentityServerConstants.ExternalCookieAuthenticationScheme);
            }
        }
    }
}
