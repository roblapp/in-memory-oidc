// ReSharper disable RedundantTypeArgumentsOfMethod
namespace Authentication.Server.Controllers
{
    using System;
    using System.Threading.Tasks;
    using Authentication.Server.Filters;
    using Authentication.Server.Services.Login;
    using Authentication.Server.Services.ViewServices;
    using Authentication.Server.ViewModels.Account;
    using IdentityServer4.Events;
    using IdentityServer4.Extensions;
    using IdentityServer4.Services;
    using Microsoft.AspNetCore.Authentication;
    using Microsoft.AspNetCore.Mvc;

    [SecurityHeaders]
    public class AccountController : Controller
    {
        private readonly IAccountViewService accountViewService;
        private readonly IIdentityServerInteractionService interactionService;
        private readonly IExternalLoginService externalLoginService;
        private readonly ILocalLoginService localLoginService;
        private readonly IEventService eventsService;

        public AccountController(
            IAccountViewService accountViewService,
            IIdentityServerInteractionService interactionService,
            IExternalLoginService externalLoginService,
            ILocalLoginService localLoginService,
            IEventService eventsService)
        {
            this.interactionService = interactionService;
            this.externalLoginService = externalLoginService;
            this.localLoginService = localLoginService;
            this.accountViewService = accountViewService;
            this.eventsService = eventsService;
        }

        /// <summary>
        /// Show login page
        /// </summary>
        [HttpGet]
        public async Task<IActionResult> Login(string returnUrl)
        {
            var vm = await this.accountViewService.BuildLoginViewModelAsync(returnUrl);

            if (vm.IsExternalLoginOnly)
            {
                // only one option for logging in
                return await this.ExternalLogin(vm.ExternalLoginScheme, returnUrl);
            }

            return this.View(vm);
        }

        /// <summary>
        /// Handle postback from username/password login
        /// </summary>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginInputModel model, string button)
        {
            if (this.ModelState.IsValid)
            {
                LocalLoginProcessResult result = await this.localLoginService.DoLocalLoginProcessAsync(model, this.HttpContext);

                if (result.Successful)
                {
                    // make sure the returnUrl is still valid, and if yes - redirect back to authorize endpoint or a local page
                    if (this.interactionService.IsValidReturnUrl(model.ReturnUrl) || this.Url.IsLocalUrl(model.ReturnUrl))
                    {
                        return this.Redirect(model.ReturnUrl);
                    }

                    return this.Redirect("~/");
                }

                this.ModelState.AddModelError("", AccountOptions.InvalidCredentialsErrorMessage);
            }

            // something went wrong, show form with error
            var vm = await this.accountViewService.BuildLoginViewModelAsync(model);
            return this.View(vm);
        }

        /// <summary>
        /// initiate roundtrip to external authentication provider
        /// </summary>
        [HttpGet]
        public async Task<IActionResult> ExternalLogin(string provider, string returnUrl)
        {
            if (AccountOptions.WindowsAuthenticationSchemeName == provider)
            {
                //TODO replace with a view
                throw new NotImplementedException("Windows Authentication is not supported");
            }

            var props = new AuthenticationProperties
                        {
                            RedirectUri = this.Url.Action("ExternalLoginCallback"),
                            Items =
                            {
                                { "returnUrl", returnUrl },
                                { "scheme", provider }
                            }
                        };
            return await Task.FromResult<ChallengeResult>(this.Challenge(props, provider));
        }

        /// <summary>
        /// Post processing of external authentication
        /// </summary>
        [HttpGet]
        public async Task<IActionResult> ExternalLoginCallback(string returnUrl)
        {
            await this.externalLoginService.DoExternalLoginCallbackProcessAsync(this.HttpContext);

            // validate return URL and redirect back to authorization endpoint or a local page
            if (this.interactionService.IsValidReturnUrl(returnUrl) || this.Url.IsLocalUrl(returnUrl))
            {
                return this.Redirect(returnUrl);
            }

            return this.Redirect("~/");
        }

        /// <summary>
        /// Show logout page
        /// </summary>
        [HttpGet]
        public async Task<IActionResult> Logout(string logoutId)
        {
            var vm = await this.accountViewService.BuildLogoutViewModelAsync(logoutId);

            return await this.Logout(vm);
        }

        /// <summary>
        /// Handle logout page postback
        /// </summary>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Logout(LogoutInputModel model)
        {
            var vm = await this.accountViewService.BuildLoggedOutViewModelAsync(model.LogoutId);

            var user = this.HttpContext.User;
            if (user?.Identity.IsAuthenticated == true)
            {
                await this.HttpContext.SignOutAsync();

                // raise the logout event
                await this.eventsService.RaiseAsync(new UserLogoutSuccessEvent(user.GetSubjectId(), user.GetDisplayName()));
            }

            return this.View("LoggedOut", vm);

            //Google doesn't support Logout at the moment. See comments here https://github.com/IdentityServer/IdentityServer4/issues/1531
            //if (!vm.TriggerExternalSignout)
            //{
            //    return this.View("LoggedOut", vm);
            //}

            //// build a return URL so the upstream provider will redirect back
            //// to us after the user has logged out. this allows us to then
            //// complete our single sign-out processing.
            //var url = this.Url.Action("Logout", new { logoutId = vm.LogoutId });

            //// this triggers a redirect to the external provider for sign-out
            //return this.SignOut(
            //    new AuthenticationProperties
            //    {
            //        RedirectUri = url
            //    },
            //    vm.ExternalAuthenticationScheme);
        }
    }
}