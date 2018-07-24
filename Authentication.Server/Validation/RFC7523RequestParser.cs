// ReSharper disable InconsistentNaming
namespace Authentication.Server.Validation
{
    using System;
    using System.Collections.Specialized;
    using System.IdentityModel.Tokens.Jwt;
    using System.Threading.Tasks;
    using Authentication.Server.Extensions;
    using Authentication.Server.Models;
    using Microsoft.Extensions.Logging;

    public interface IRFC7523RequestParser
    {
        Task<RFC7523RequestModel> ParseAsync(NameValueCollection rawRequest);
    }

    public class RFC7523RequestParser : IRFC7523RequestParser
    {
        private readonly ILogger<RFC7523RequestParser> logger;

        public RFC7523RequestParser(ILogger<RFC7523RequestParser> logger)
        {
            this.logger = logger;
        }

        public Task<RFC7523RequestModel> ParseAsync(NameValueCollection rawRequest)
        {
            var assertion = rawRequest["assertion"];
            if (string.IsNullOrWhiteSpace(assertion))
            {
                throw new ArgumentException("Parameter 'assertion' was missing");
            }

            //*** IMPORTANT ***
            //This step of the process is looking at the data in the token. At this point it is
            //NOT being validated. We simply need to get the user device id out of the JWT header
            //so we know which public key to use for validation. Validation is a subsequent step.
            //ReadJwtToken must NEVER be used for validation.
            var handler = new JwtSecurityTokenHandler();
            var jwtSecurityToken = handler.ReadJwtToken(assertion);

            if (jwtSecurityToken == null)
            {
                throw new ArgumentException("Parameter 'assertion' was invalid (JWT assertion could not be read by the JWT Security Token handler)");
            }

            if (jwtSecurityToken.Header == null)
            {
                throw new ArgumentException("The given assertion was missing a JWT header");
            }

            //KeyId = user device credential id
            var keyId = jwtSecurityToken.Header.Kid;
            if (string.IsNullOrWhiteSpace(keyId))
            {
                throw new ArgumentException("The given assertion was missing a 'kid' claim in the JWT header");
            }

            var result = new RFC7523RequestModel
                         {
                            Assertion = assertion,
                            KeyId = new Guid(keyId)
                         };

            this.logger.LogDebug("RFC7523 request was successfully parsed");
            this.logger.LogDebug(result.AsJson());

            return Task.FromResult(result);
        }
    }
}
