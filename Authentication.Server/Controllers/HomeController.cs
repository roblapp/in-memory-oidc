// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Authentication.Server.Controllers
{
    using System.Threading.Tasks;
    using Authentication.Server.Filters;
    using Authentication.Server.ViewModels.Home;
    using IdentityServer4.Services;
    using Microsoft.AspNetCore.Mvc;

    [SecurityHeaders]
    public class HomeController : Controller
    {
        private readonly IIdentityServerInteractionService interactionService;

        public HomeController(IIdentityServerInteractionService interactionService)
        {
            this.interactionService = interactionService;
        }

        public IActionResult Index()
        {
            return this.View();
        }

        /// <summary>
        /// Shows the error page
        /// </summary>
        public async Task<IActionResult> Error(string errorId)
        {
            var vm = new ErrorViewModel();

            // retrieve error details from identityserver
            var message = await this.interactionService.GetErrorContextAsync(errorId);
            if (message != null)
            {
                vm.Error = message;
            }

            return this.View("Error", vm);
        }
    }
}