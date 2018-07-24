namespace Authentication.Api.Controllers
{
    using System.Linq;
    using Microsoft.AspNetCore.Authorization;
    using Microsoft.AspNetCore.Mvc;
    using Microsoft.Extensions.Logging;
    using Newtonsoft.Json;
    using Newtonsoft.Json.Serialization;

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
            this.logger.LogDebug(this.User.Claims.Select(c => new { c.Type, c.Value }).AsJson());
            //this.logger.LogDebug($"Access token) {this.User.Claims.First(x => x.Type == "access_token")?.Value}");

            return new JsonResult(from c in this.User.Claims select new { c.Type, c.Value });
        }
    }

    public static class JsonExtensions
    {
        public static string AsJson(this object obj, bool showNullValues = false)
        {
            if (obj == null)
            {
                return null;
            }

            return JsonConvert.SerializeObject(
                obj,
                new JsonSerializerSettings
                {
                    NullValueHandling = showNullValues ? NullValueHandling.Include : NullValueHandling.Ignore,
                    ReferenceLoopHandling = ReferenceLoopHandling.Ignore,
                    PreserveReferencesHandling = PreserveReferencesHandling.None, // removes returning $id, $ref
                    DateFormatHandling = DateFormatHandling.IsoDateFormat,
                    Formatting = Formatting.Indented,
                    ContractResolver = new CamelCasePropertyNamesContractResolver()
                });
        }
    }
}
