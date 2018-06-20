namespace Authentication.Server.Services.ViewServices
{
    using System;
    using System.Linq;
    using System.Threading.Tasks;
    using Authentication.Server.ViewModels.Account;
    using IdentityModel;
    using IdentityServer4;
    using IdentityServer4.Extensions;
    using IdentityServer4.Services;
    using IdentityServer4.Stores;
    using Microsoft.AspNetCore.Authentication;
    using Microsoft.AspNetCore.Http;
    using Microsoft.Extensions.Logging;

    public class AccountViewService : BaseService, IAccountViewService
    {
        private readonly IIdentityServerInteractionService interactionService;
        private readonly IClientStore clientStore;
        private readonly IHttpContextAccessor httpContextAccessor;
        private readonly IAuthenticationSchemeProvider schemeProvider;

        public AccountViewService(
            ILogger<AccountViewService> logger,
            IIdentityServerInteractionService interactionService,
            IClientStore clientStore,
            IHttpContextAccessor httpContextAccessor,
            IAuthenticationSchemeProvider schemeProvider)
            : base((ILogger)logger)
        {
            this.interactionService = interactionService;
            this.clientStore = clientStore;
            this.httpContextAccessor = httpContextAccessor;
            this.schemeProvider = schemeProvider;
        }

        public async Task<LoginViewModel> BuildLoginViewModelAsync(string returnUrl)
        {
            var context = await this.interactionService.GetAuthorizationContextAsync(returnUrl);
            if (context?.IdP != null)
            {
                // this is meant to short circuit the UI and only trigger the one external IdP
                return new LoginViewModel
                       {
                           EnableLocalLogin = false,
                           ReturnUrl = returnUrl,
                           Username = context.LoginHint,
                           ExternalProviders = new[] { new ExternalProvider { AuthenticationScheme = context.IdP } }
                       };
            }

            //var schemes = this.httpContextAccessor.HttpContext.Authentication.GetAuthenticationSchemes().ToList();
            var schemes = await this.schemeProvider.GetAllSchemesAsync();

            var providers = Enumerable.Where<AuthenticationScheme>(schemes, x => x.DisplayName != null)
                .Select(x => new ExternalProvider
                             {
                                 DisplayName = x.DisplayName,
                                 AuthenticationScheme = x.Name
                             }).ToList();

            var allowLocal = true;
            //TODO fix
            if (context?.ClientId != null)
            {
                var client = await IClientStoreExtensions.FindEnabledClientByIdAsync(this.clientStore, context.ClientId);
                if (client != null)
                {
                    allowLocal = client.EnableLocalLogin;

                    if (client.IdentityProviderRestrictions != null && client.IdentityProviderRestrictions.Any())
                    {
                        providers = providers.Where(provider => client.IdentityProviderRestrictions.Contains(provider.AuthenticationScheme)).ToList();
                    }
                }
            }

            return new LoginViewModel
                   {
                       AllowRememberLogin = AccountOptions.AllowRememberLogin,
                       EnableLocalLogin = allowLocal && AccountOptions.AllowLocalLogin,
                       ReturnUrl = returnUrl,
                       Username = context?.LoginHint,
                       ExternalProviders = providers.ToArray()
                   };
        }

        public async Task<LoginViewModel> BuildLoginViewModelAsync(LoginInputModel model)
        {
            var vm = await this.BuildLoginViewModelAsync(model.ReturnUrl);
            vm.Username = model.Username;
            vm.RememberLogin = model.RememberLogin;
            return vm;
        }

        public Task<LogoutViewModel> BuildLogoutViewModelAsync(string logoutId)
        {
            var vm = new LogoutViewModel
                     {
                         LogoutId = logoutId,
                         ShowLogoutPrompt = false
                     };

            //var user = this.httpContextAccessor.HttpContext.User;
            //if (user == null || user.Identity.IsAuthenticated == false)
            //{
            //    // if the user is not authenticated, then just show logged out page
            //    vm.ShowLogoutPrompt = false;
            //    return vm;
            //}

            //var context = await this.interactionService.GetLogoutContextAsync(logoutId);
            //if (context?.ShowSignoutPrompt == false)
            //{
            //    // it's safe to automatically sign-out
            //    vm.ShowLogoutPrompt = false;
            //    return vm;
            //}

            // show the logout prompt. this prevents attacks where the user
            // is automatically signed out by another malicious web page.
            return Task.FromResult(vm);
        }

        public async Task<LoggedOutViewModel> BuildLoggedOutViewModelAsync(string logoutId)
        {
            // get context information (client name, post logout redirect URI and iframe for federated signout)
            var logout = await this.interactionService.GetLogoutContextAsync(logoutId);

            var vm = new LoggedOutViewModel
                     {
                         AutomaticRedirectAfterSignOut = true,
                         PostLogoutRedirectUri = logout?.PostLogoutRedirectUri,
                         ClientName = logout?.ClientId,
                         SignOutIframeUrl = logout?.SignOutIFrameUrl,
                         LogoutId = logoutId
                     };

            var user = this.httpContextAccessor.HttpContext.User;
            if (user == null) return vm;

            var identityProvider = user.FindFirst(JwtClaimTypes.IdentityProvider)?.Value;
            if (identityProvider != null && !string.Equals(identityProvider, IdentityServerConstants.LocalIdentityProvider, StringComparison.InvariantCultureIgnoreCase))
            {
                var providerSupportsSignout = await HttpContextExtensions.GetSchemeSupportsSignOutAsync(this.httpContextAccessor.HttpContext, identityProvider);
                if (providerSupportsSignout)
                {
                    if (vm.LogoutId == null)
                    {
                        // if there's no current logout context, we need to create one
                        // this captures necessary info from the current logged in user
                        // before we signout and redirect away to the external IdP for signout
                        vm.LogoutId = await this.interactionService.CreateLogoutContextAsync();
                    }

                    vm.ExternalAuthenticationScheme = identityProvider;
                }

                if (vm.LogoutId == null)
                {
                    // if there's no current logout context, we need to create one
                    // this captures necessary info from the current logged in user
                    // before we signout and redirect away to the external IdP for signout
                    vm.LogoutId = await this.interactionService.CreateLogoutContextAsync();
                }

                vm.ExternalAuthenticationScheme = identityProvider;
            }

            return vm;
        }
    }
}
