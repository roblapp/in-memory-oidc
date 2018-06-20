namespace Authentication.Api.Controllers
{
    using System.Linq;
    using Microsoft.AspNetCore.Authorization;
    using Microsoft.AspNetCore.Mvc;
    using Microsoft.Extensions.Logging;

    [Route("[controller]")]
    [Authorize]
    public class IdentityController : ControllerBase
    {
        private readonly ILogger<IdentityController> logger;

        public IdentityController(ILogger<IdentityController> logger)
        {
            this.logger = logger;
        }

        [HttpGet]
        public IActionResult Get()
        {
            this.logger.LogDebug($"this.User.Identity.Name) {this.User.Identity.Name}");
            this.logger.LogDebug($"this.User.Identity.AuthenticationType) {this.User.Identity.AuthenticationType}");
            this.logger.LogDebug($"Access token) {this.User.Claims.First(x => x.Type == "access_token")?.Value}");

            return new JsonResult(from c in this.User.Claims select new { c.Type, c.Value });
        }
    }
}
