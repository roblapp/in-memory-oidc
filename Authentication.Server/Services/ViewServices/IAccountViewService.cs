namespace Authentication.Server.Services.ViewServices
{
    using System.Threading.Tasks;
    using Authentication.Server.ViewModels.Account;

    public interface IAccountViewService
    {
        Task<LoginViewModel> BuildLoginViewModelAsync(string returnUrl);

        Task<LoginViewModel> BuildLoginViewModelAsync(LoginInputModel model);

        Task<LogoutViewModel> BuildLogoutViewModelAsync(string logoutId);

        Task<LoggedOutViewModel> BuildLoggedOutViewModelAsync(string logoutId);
    }
}
