// ReSharper disable InconsistentNaming
// ReSharper disable PossibleMultipleEnumeration
namespace Authentication.Server.IdentityServer
{
    using System;
    using System.Collections.Generic;
    using System.IdentityModel.Tokens.Jwt;
    using System.IO;
    using System.Linq;
    using System.Reflection;
    using System.Security.Claims;
    using System.Security.Cryptography;
    using System.Threading.Tasks;
    using Authentication.Server.Models;
    using Authentication.Server.Validation;
    using IdentityServer4.Extensions;
    using IdentityServer4.Validation;
    using Microsoft.Extensions.Logging;
    using Microsoft.IdentityModel.Tokens;
    using Newtonsoft.Json;
    using Newtonsoft.Json.Serialization;

    public class RFC7523GrantValidator : IExtensionGrantValidator
    {
        private readonly IRFC7523RequestParser requestParser;
        private readonly ILogger<RFC7523GrantValidator> logger;

        /// <summary>
        /// Gets the grant type that this validator works with
        /// </summary>
        public string GrantType { get; } = "urn:ietf:params:oauth:grant-type:jwt-bearer";


        public RFC7523GrantValidator(
            IRFC7523RequestParser requestParser,
            ILogger<RFC7523GrantValidator> logger)
        {
            this.requestParser = requestParser;
            this.logger = logger;
        }

        /// <summary>
        /// Validates the RFC 7523 grant type. This grant type is used for SCGX native
        /// </summary>
        /// <param name="context">The extension grant validation context which contains relevant information from the token endpoint</param>
        /// <returns>success or fail inside of the context</returns>
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
            //Validate User Info

            //Success
            context.Result = new GrantValidationResult(claimsPrincipal.GetSubjectId(), this.GrantType);
            this.logger.LogInformation("Finished validating extension grant_type '{grant}'", this.GrantType);
        }

        protected virtual Task<UserDeviceCredential> GetUserDeviceCredentialByIdAsync(Guid userDeviceCredentialId)
        {
            //Read from database
            return Task.FromResult(
                new UserDeviceCredential
                {
                    UserDeviceCredentialId = userDeviceCredentialId,
                    UserId = new Guid("425b7fba-1bf1-4368-b499-178860fb75f3"),
                    DeviceId = new Guid("4b09e22b-636f-444e-9241-40aa4cc6b569")
                });
        }

        protected virtual Task<SigningCredentials> CreateSigningCredentialsAsync(UserDeviceCredential userDeviceCredential)
        {
            //This logic will convert a UDC to a SigningCredential
            var path = @"C:\Users\robert.lapp\Desktop\Debugging\Crypto\public-rsa.json";
            var rawJson = File.ReadAllText(path);
            //var rsaParameters = new RSAParameters
            //        {
            //            Exponent = Encoding.UTF8.GetBytes(userDeviceCredential.Exponent),
            //            Modulus = Encoding.UTF8.GetBytes(userDeviceCredential.Modulus)
            //        };
            var rsaParameters = JsonConvert.DeserializeObject<RSAParameters>(rawJson, new JsonSerializerSettings
                                                                                      {
                                                                                          ContractResolver = new RsaKeyContractResolver()
                                                                                      });
            var key = new RsaSecurityKey(rsaParameters) { KeyId = userDeviceCredential.UserDeviceCredentialId.ToString("D") };
            var signingCredentials = new SigningCredentials(key, "RS256");
            return Task.FromResult(signingCredentials);
        }

        protected virtual Task<ClaimsPrincipal> ValidateAssertionAsync(
            RFC7523RequestModel request,
            UserDeviceCredential userDeviceCredential,
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

    public class UserDeviceCredential
    {
        public Guid UserDeviceCredentialId { get; set; }

        public Guid UserId { get; set; }

        public Guid DeviceId { get; set; }

        public string Exponent { get; set; }

        public string Modulus { get; set; }
    }

    internal class RFC7523AssertionValidator
    {
        private readonly UserDeviceCredential userDeviceCredential;

        internal RFC7523AssertionValidator(UserDeviceCredential userDeviceCredential)
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

    internal class RsaKeyContractResolver : DefaultContractResolver
    {
        protected override JsonProperty CreateProperty(MemberInfo member, MemberSerialization memberSerialization)
        {
            var property = base.CreateProperty(member, memberSerialization);

            property.Ignored = false;

            return property;
        }
    }
}
