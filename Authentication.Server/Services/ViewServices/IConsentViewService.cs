namespace Authentication.Server.Services.ViewServices
{
    using System.Threading.Tasks;
    using Authentication.Server.ViewModels.Consent;

    public interface IConsentViewService
    {
        Task<ProcessConsentResult> ProcessConsent(ConsentInputModel model);

        Task<ConsentViewModel> BuildViewModelAsync(string returnUrl, ConsentInputModel model = null);
    }
}
