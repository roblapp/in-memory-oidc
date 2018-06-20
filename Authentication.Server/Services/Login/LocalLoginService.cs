namespace Authentication.Server.Services.Login
{
    using System;
    using System.Threading.Tasks;
    using Authentication.Server.Dtos;
    using Authentication.Server.Services.Users;
    using Authentication.Server.ViewModels.Account;
    using IdentityServer4.Events;
    using IdentityServer4.Services;
    using Microsoft.AspNetCore.Authentication;
    using Microsoft.AspNetCore.Http;
    using Microsoft.Extensions.Logging;

    public interface ILocalLoginService : IBaseService
    {
        Task<LocalLoginProcessResult> DoLocalLoginProcessAsync(LoginInputModel loginModel, HttpContext httpContext);

        Task<UserDto> AuthenticateLocalUserAsync(string username, string password);
    }


    public class LocalLoginService : BaseService, ILocalLoginService
    {
        private readonly IEventService eventsService;
        private readonly IUserService userService;

        public LocalLoginService(ILogger<LocalLoginService> logger, IEventService eventsService, IUserService userService)
            : base(logger)
        {
            this.eventsService = eventsService;
            this.userService = userService;
        }

        public async Task<LocalLoginProcessResult> DoLocalLoginProcessAsync(LoginInputModel loginModel, HttpContext httpContext)
        {
            var user = await this.AuthenticateLocalUserAsync(loginModel.Username, loginModel.Password);

            // validate username/password
            if (user != null)
            {
                await this.eventsService.RaiseAsync(new UserLoginSuccessEvent(user.Username, user.UserId, user.Username));

                AuthenticationProperties props = null;
                // only set explicit expiration here if persistent.
                // otherwise we reply upon expiration configured in cookie middleware.
                if (AccountOptions.AllowRememberLogin && loginModel.RememberLogin)
                {
                    props = new AuthenticationProperties
                            {
                                IsPersistent = true,
                                ExpiresUtc = DateTimeOffset.UtcNow.Add(AccountOptions.RememberMeLoginDuration)
                            };
                }

                // issue authentication cookie with subject ID and username
                await httpContext.SignInAsync(user.UserId, user.Username, props);

                return new LocalLoginProcessResult { Successful = true };
            }

            await this.eventsService.RaiseAsync(new UserLoginFailureEvent(loginModel.Username, "invalid credentials"));

            return new LocalLoginProcessResult { Successful = false };
        }

        public Task<UserDto> AuthenticateLocalUserAsync(string username, string password)
        {
            var user = this.userService.GetSingleOrDefaultAsync(
                x =>
                    x.IsActive
                    &&
                    string.Equals(x.Username, username, StringComparison.InvariantCultureIgnoreCase)
                    &&
                    string.Equals(x.Password, password));

            return user;
        }
    }
}
