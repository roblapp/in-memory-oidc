namespace Authentication.Server.ViewModels.Consent
{
    public class ProcessConsentResult
    {
        public bool IsRedirect => this.RedirectUri != null;

        public string RedirectUri { get; set; }

        public bool ShowView => this.ViewModel != null;

        public ConsentViewModel ViewModel { get; set; }

        public bool HasValidationError => this.ValidationError != null;

        public string ValidationError { get; set; }
    }
}
