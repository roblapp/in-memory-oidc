// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Authentication.Server.Services.ViewServices
{
    using System.Linq;
    using System.Threading.Tasks;
    using Authentication.Server.Extensions;
    using Authentication.Server.ViewModels.Consent;
    using IdentityServer4;
    using IdentityServer4.Models;
    using IdentityServer4.Services;
    using IdentityServer4.Stores;
    using Microsoft.Extensions.Logging;

    public class ConsentViewService : BaseService, IConsentViewService
    {
        private readonly IClientStore clientStore;
        private readonly IResourceStore resourceStore;
        private readonly IIdentityServerInteractionService interactionService;

        public ConsentViewService(ILogger<ConsentViewService> logger, IIdentityServerInteractionService interactionService, IClientStore clientStore, IResourceStore resourceStore)
            : base((ILogger)logger)
        {
            this.interactionService = interactionService;
            this.clientStore = clientStore;
            this.resourceStore = resourceStore;
        }

        public async Task<ProcessConsentResult> ProcessConsent(ConsentInputModel model)
        {
            var result = new ProcessConsentResult();

            ConsentResponse grantedConsent = null;

            // user clicked 'no' - send back the standard 'access_denied' response
            if (model.Button == "no")
            {
                grantedConsent = ConsentResponse.Denied;
            }
            else if (model.Button == "yes")
            {
                // user clicked 'yes' - validate the data
                // if the user consented to any scope, build the response model
                if (model.ScopesConsented != null && model.ScopesConsented.Any())
                {
                    var scopes = model.ScopesConsented;
                    if (ConsentOptions.EnableOfflineAccess == false)
                    {
                        scopes = scopes.Where(x => x != IdentityServerConstants.StandardScopes.OfflineAccess);
                    }

                    grantedConsent = new ConsentResponse
                                     {
                                         RememberConsent = model.RememberConsent,
                                         ScopesConsented = scopes.ToArray()
                                     };
                }
                else
                {
                    result.ValidationError = ConsentOptions.MustChooseOneErrorMessage;
                }
            }
            else
            {
                result.ValidationError = ConsentOptions.InvalidSelectionErrorMessage;
            }

            if (grantedConsent != null)
            {
                // validate return url is still valid
                var request = await this.interactionService.GetAuthorizationContextAsync(model.ReturnUrl);
                if (request == null) return result;

                // communicate outcome of consent back to identityserver
                await this.interactionService.GrantConsentAsync(request, grantedConsent);

                // indiate that's it ok to redirect back to authorization endpoint
                result.RedirectUri = model.ReturnUrl;
            }
            else
            {
                // we need to redisplay the consent UI
                result.ViewModel = await this.BuildViewModelAsync(model.ReturnUrl, model);
            }

            return result;
        }


        public async Task<ConsentViewModel> BuildViewModelAsync(string returnUrl, ConsentInputModel model = null)
        {
            var request = await this.interactionService.GetAuthorizationContextAsync(returnUrl);
            if (request == null)
            {
                LoggerExtensions.LogError(this.Logger, "No consent request matching request: {0}", returnUrl);
                return null;
            }

            var client = await IClientStoreExtensions.FindEnabledClientByIdAsync(this.clientStore, request.ClientId);
            if (client == null)
            {
                LoggerExtensions.LogError(this.Logger, "Invalid client id: {0}", request.ClientId);
                return null;
            }

            var resources = await IResourceStoreExtensions.FindEnabledResourcesByScopeAsync(this.resourceStore, request.ScopesRequested);
            if (resources != null && (resources.IdentityResources.Any() || resources.ApiResources.Any()))
            {
                return this.CreateConsentViewModel(model, returnUrl, client, resources);
            }

            LoggerExtensions.LogError(this.Logger, "No scopes matching: {0}", request.ScopesRequested.Aggregate((x, y) => x + ", " + y));

            return null;
        }

        private ConsentViewModel CreateConsentViewModel(ConsentInputModel model, string returnUrl, Client client, Resources resources)
        {
            var vm = new ConsentViewModel
                     {
                         RememberConsent = model?.RememberConsent ?? true,
                         ScopesConsented = model?.ScopesConsented ?? Enumerable.Empty<string>(),
                         ReturnUrl = returnUrl,
                         ClientName = client.ClientName,
                         ClientUrl = client.ClientUri,
                         ClientLogoUrl = client.LogoUri,
                         AllowRememberConsent = client.AllowRememberConsent
                     };
            
            vm.IdentityScopes = resources.IdentityResources.Select<IdentityResource, ScopeViewModel>(
                                        x => this.CreateScopeViewModel(x, vm.ScopesConsented.Contains(x.Name) || model == null)).ToArray();

            var temp = resources.ApiResources.SelectMany(x => x.Scopes).Filter(x => x.Name, x => x);

            vm.ResourceScopes = temp.Select<Scope, ScopeViewModel>(
                x => this.CreateScopeViewModel(x, vm.ScopesConsented.Contains(x.Name) || model == null)).ToArray();

            if (ConsentOptions.EnableOfflineAccess && resources.OfflineAccess)
            {
                var scopeViewModel = this.GetOfflineAccessScope(vm.ScopesConsented.Contains<string>(IdentityServerConstants.StandardScopes.OfflineAccess) || model == null);

                vm.ResourceScopes = vm.ResourceScopes.Union(
                    new ScopeViewModel[]
                    {
                        scopeViewModel
                    });
            }

            return vm;
        }

        public ScopeViewModel CreateScopeViewModel(IdentityResource identity, bool check)
        {
            return new ScopeViewModel
            {
                Name = identity.Name,
                DisplayName = identity.DisplayName,
                Description = identity.Description,
                Emphasize = identity.Emphasize,
                Required = identity.Required,
                Checked = check || identity.Required
            };
        }

        public ScopeViewModel CreateScopeViewModel(Scope scope, bool check)
        {
            return new ScopeViewModel
            {
                Name = scope.Name,
                DisplayName = scope.DisplayName,
                Description = scope.Description,
                Emphasize = scope.Emphasize,
                Required = scope.Required,
                Checked = check || scope.Required,
            };
        }

        private ScopeViewModel GetOfflineAccessScope(bool check)
        {
            return new ScopeViewModel
            {
                Name = IdentityServerConstants.StandardScopes.OfflineAccess,
                DisplayName = ConsentOptions.OfflineAccessDisplayName,
                Description = ConsentOptions.OfflineAccessDescription,
                Emphasize = true,
                Checked = check
            };
        }
    }
}

