// ReSharper disable InconsistentNaming
// ReSharper disable PossibleMultipleEnumeration
namespace Authentication.Server.IdentityServer
{
    using System;
    using System.Collections.Generic;
    using System.IdentityModel.Tokens.Jwt;
    using System.Linq;
    using System.Security.Claims;
    using System.Security.Cryptography;
    using System.Threading.Tasks;
    using Authentication.Server.Dtos;
    using Authentication.Server.Models;
    using Authentication.Server.Services;
    using Authentication.Server.Validation;
    using IdentityServer4.Extensions;
    using IdentityServer4.Validation;
    using Microsoft.Extensions.Logging;
    using Microsoft.IdentityModel.Tokens;

    public class RFC7523GrantValidator : IExtensionGrantValidator
    {
        private readonly IRFC7523RequestParser requestParser;
        private readonly IUserDeviceCredentialService userDeviceCredentialService;
        private readonly ILogger<RFC7523GrantValidator> logger;
        
        public string GrantType { get; } = "urn:ietf:params:oauth:grant-type:jwt-bearer";
        

        public RFC7523GrantValidator(
            IRFC7523RequestParser requestParser,
            IUserDeviceCredentialService userDeviceCredentialService,
            ILogger<RFC7523GrantValidator> logger)
        {
            this.requestParser = requestParser;
            this.userDeviceCredentialService = userDeviceCredentialService;
            this.logger = logger;
        }

        public async Task ValidateAsync(ExtensionGrantValidationContext context)
        {
            this.logger.LogInformation("Validating extension grant_type '{grant}'", this.GrantType);
            //Note: the class that calls this method handles all Exceptions in a consistent manner
            var parsedRequest = await this.requestParser.ParseAsync(context.Request.Raw);
            var userDeviceCredential = await this.GetUserDeviceCredentialByIdAsync(parsedRequest.KeyId);
            if (userDeviceCredential == null)
            {
                throw new ArgumentException($"Cannot find user credential '{parsedRequest.KeyId}'");
            }
            var signingCredentials = await this.CreateSigningCredentialsAsync(userDeviceCredential);
            var claimsPrincipal = await this.ValidateAssertionAsync(parsedRequest, userDeviceCredential, signingCredentials);

            //Success
            context.Result = new GrantValidationResult(claimsPrincipal.GetSubjectId(), this.GrantType);
            this.logger.LogInformation("Finished validating extension grant_type '{grant}'", this.GrantType);
        }

        public async Task<UserDeviceCredentialDto> GetUserDeviceCredentialByIdAsync(Guid userDeviceCredentialId)
        {
            var userDeviceCredential = await this.userDeviceCredentialService.GetSingleOrDefaultAsync(x => x.UserDeviceCredentialId == userDeviceCredentialId);

            return userDeviceCredential;
        }

        public Task<SigningCredentials> CreateSigningCredentialsAsync(UserDeviceCredentialDto userDeviceCredential)
        {
            var rsaParameters = new RSAParameters
                                {
                                    Exponent = Convert.FromBase64String(userDeviceCredential.Exponent),
                                    Modulus = Convert.FromBase64String(userDeviceCredential.Modulus)
                                };
            var key = new RsaSecurityKey(rsaParameters) { KeyId = userDeviceCredential.UserDeviceCredentialId.ToString("D") };
            var signingCredentials = new SigningCredentials(key, "RS256");
            return Task.FromResult(signingCredentials);
        }

        public Task<ClaimsPrincipal> ValidateAssertionAsync(
            RFC7523RequestModel request,
            UserDeviceCredentialDto userDeviceCredential,
            SigningCredentials signingCredentials)
        {
            var validator = new RFC7523AssertionValidator(userDeviceCredential);
            var tokenValidationParameters = new TokenValidationParameters
                                            {
                                                IssuerSigningKey = signingCredentials.Key,
                                                ValidateIssuerSigningKey = true,

                                                ValidateIssuer = true,
                                                IssuerValidator = validator.ValidateIssuer,

                                                ValidateAudience = true,
                                                AudienceValidator = validator.ValidateAudience,

                                                RequireSignedTokens = true,
                                                RequireExpirationTime = true
                                            };

            var handler = new JwtSecurityTokenHandler();
            var result = handler.ValidateToken(request.Assertion, tokenValidationParameters, out var _);
            return Task.FromResult(result);
        }
    }
    
    internal class RFC7523AssertionValidator
    {
        private readonly UserDeviceCredentialDto userDeviceCredential;

        static RFC7523AssertionValidator()
        {
            JwtSecurityTokenHandler.DefaultInboundClaimTypeMap.Clear();
        }

        internal RFC7523AssertionValidator(UserDeviceCredentialDto userDeviceCredential)
        {
            this.userDeviceCredential = userDeviceCredential;
        }

        //The issuer is the device id
        public string ValidateIssuer(string issuer, SecurityToken token, TokenValidationParameters parameters)
        {
            var jwtSecurityToken = token as JwtSecurityToken;

            if (jwtSecurityToken == null)
            {
                throw new ArgumentException("Issuer validation failed. Failed to parse SecurityToken as a JwtSecurityToken");
            }

            if (!Guid.TryParse(issuer, out Guid issuerAsGuid))
            {
                throw new ArgumentException("Issuer validation failed. The supplied 'iss' claim was invalid and could not be parsed as a guid");
            }
            
            var expectedIssuer = this.userDeviceCredential.DeviceId;
            if (issuerAsGuid != expectedIssuer)
            {
                throw new ArgumentException("Issuer validation failed. The supplied 'iss' claim was invalid and did not match the expected issuer.");
            }

            return issuer;
        }

        public bool ValidateAudience(IEnumerable<string> audiences, SecurityToken token, TokenValidationParameters parameters)
        {
            var tokenEndpoint = this.GetTokenEndpoint();

            if (audiences == null || !audiences.Any())
            {
                return false;
            }

            if (audiences.Count() != 1)
            {
                return false;
            }

            foreach (var audience in audiences)
            {
                if (string.Equals(audience, tokenEndpoint, StringComparison.InvariantCultureIgnoreCase))
                {
                    return true;
                }
            }

            return false;
        }

        private string GetTokenEndpoint()
        {
            return "http://localhost:5000/connect/token";
        }
    }
}
