namespace Authentication.Clients.Native
{
    using System;
    using System.Collections.Generic;
    using System.Globalization;
    using System.IdentityModel.Tokens.Jwt;
    using System.IO;
    using System.Linq;
    using System.Net.Http;
    using System.Net.Http.Headers;
    using System.Reflection;
    using System.Security.Claims;
    using System.Security.Cryptography;
    using System.Threading.Tasks;
    using IdentityModel;
    using IdentityModel.Client;
    using Microsoft.IdentityModel.Tokens;
    using Newtonsoft.Json;
    using Newtonsoft.Json.Serialization;

    public class Program
    {
        public static void Main(string[] args)
        {
            RunAsync().GetAwaiter().GetResult();
            
            Console.WriteLine("Press any key to exit");
            Console.ReadKey();
        }

        public static async Task RunAsync()
        {
            var tokenEndpoint = "http://localhost:5000/connect/token";
            var scopes = "openid profile api.resource.read api.resource.write";
            var clientId = "jwt-bearer-grant-client";
            var signingCredentials = CreateSigningCredentials();
            var jwt = CreateJwt(
                "d1eaa073-0feb-48ad-bad2-0592963b4203",
                tokenEndpoint,
                signingCredentials,
                new KeyValuePair<string, string>("sub", "fb4a6d23-e383-4b64-95f5-5b62601ac9cb"),
                new KeyValuePair<string, string>("client_id", clientId));
            var tokenClient = new TokenClient(tokenEndpoint, clientId);
            var tokenResponse = await tokenClient.RequestAssertionAsync("urn:ietf:params:oauth:grant-type:jwt-bearer", jwt, scopes);

            if (tokenResponse == null)
            {
                Console.WriteLine("TokenResponse was null");
            }
            else if (tokenResponse.IsError)
            {
                Console.WriteLine(tokenResponse.Error);
                Console.WriteLine(tokenResponse.ErrorDescription);
            }
            else
            {
                Console.WriteLine("Retrieved access token");
                Console.WriteLine(tokenResponse.AccessToken);

                using (var httpClient = new HttpClient())
                {
                    httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", tokenResponse.AccessToken);
                    var httpResponseMessage = await httpClient.SendAsync(new HttpRequestMessage(HttpMethod.Get, "http://localhost:5001/identity"));

                    var rawContent = await httpResponseMessage.Content.ReadAsStringAsync();

                    Console.WriteLine(JsonConvert.DeserializeObject<List<ClaimLite>>(rawContent).AsJson());
                }
            }
        }

        public static string CreateJwt(
            string issuer,
            string audience,
            SigningCredentials signingCredentials,
            params KeyValuePair<string, string>[] claims)
        {
            var jwtHeader = CreateJwtHeader(signingCredentials);
            var claimsToPutInToken = claims.Select(x => new Claim(x.Key, x.Value)).ToList();

            var now = DateTimeOffset.UtcNow.UtcDateTime;
            var tokenLifetime = 60 * 60;

            var jwtPayload = new JwtPayload(
                issuer,
                audience,
                claimsToPutInToken,
                now,
                now.AddSeconds(tokenLifetime),
                now);

            var handler = new JwtSecurityTokenHandler();
            var jwtSecurityToken = new JwtSecurityToken(jwtHeader, jwtPayload);
            return handler.WriteToken(jwtSecurityToken);
        }

        private static JwtHeader CreateJwtHeader(SigningCredentials signingCredentials)
        {
            if (signingCredentials == null)
            {
                throw new InvalidOperationException("No signing credential is configured. Can't create JWT token");
            }

            var header = new JwtHeader(signingCredentials);

            // emit x5t claim for backwards compatibility with v4 of MS JWT library
            if (signingCredentials.Key is X509SecurityKey x509Key)
            {
                var cert = x509Key.Certificate;
                if (DateTimeOffset.UtcNow.UtcDateTime > cert.NotAfter)
                {
                    Console.WriteLine("Certificate {0} has expired on {1}", cert.Subject, cert.NotAfter.ToString(CultureInfo.InvariantCulture));
                }

                header["x5t"] = Base64Url.Encode(cert.GetCertHash());
            }

            return header;
        }

        private static SigningCredentials CreateSigningCredentials()
        {
            var fullPath = Path.Combine(Directory.GetCurrentDirectory(), "private-rsa.json");

            if (!File.Exists(fullPath))
            {
                throw new ArgumentException($"File path '{fullPath}' does not exist");
            }

            var rawJson = File.ReadAllText(fullPath);

            var rsaParameters = JsonConvert.DeserializeObject<RSAParameters>(
                rawJson,
                new JsonSerializerSettings
                {
                    ContractResolver = new RsaKeyContractResolver()
                });

            Console.WriteLine(Convert.ToBase64String(rsaParameters.Exponent));
            Console.WriteLine(Convert.ToBase64String(rsaParameters.Modulus));

            var key = new RsaSecurityKey(rsaParameters) { KeyId = "12bf406a-ac37-43a2-8c5e-fcfc4bfa1f9f" };
            var signingCredentials = new SigningCredentials(key, "RS256");
            return signingCredentials;
        }
    }

    public class RsaKeyContractResolver : DefaultContractResolver
    {
        protected override JsonProperty CreateProperty(MemberInfo member, MemberSerialization memberSerialization)
        {
            var property = base.CreateProperty(member, memberSerialization);

            property.Ignored = false;

            return property;
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

    public class ClaimLite
    {
        public string Type { get; set; }

        public string Value { get; set; }
    }
}
