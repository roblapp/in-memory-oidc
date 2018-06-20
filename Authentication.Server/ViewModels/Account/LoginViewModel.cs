namespace Authentication.Server.ViewModels.Account
{
    using System;
    using System.Collections.Generic;
    using System.Linq;

    public class LoginViewModel : LoginInputModel
    {
        public bool AllowRememberLogin { get; set; }
        public bool EnableLocalLogin { get; set; }

        public IEnumerable<ExternalProvider> ExternalProviders { get; set; }
        public IEnumerable<ExternalProvider> VisibleExternalProviders => Enumerable.Where(this.ExternalProviders, x => !String.IsNullOrWhiteSpace(x.DisplayName));

        public bool IsExternalLoginOnly => this.EnableLocalLogin == false && this.ExternalProviders?.Count() == 1;
        public string ExternalLoginScheme => this.ExternalProviders?.SingleOrDefault()?.AuthenticationScheme;
    }
}