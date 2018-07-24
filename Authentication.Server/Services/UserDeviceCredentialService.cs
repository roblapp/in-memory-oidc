namespace Authentication.Server.Services
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Reflection;
    using System.Security.Cryptography;
    using System.Threading.Tasks;
    using Authentication.Server.Dtos;
    using Newtonsoft.Json;
    using Newtonsoft.Json.Serialization;

    public interface IUserDeviceCredentialService
    {
        Task<UserDeviceCredentialDto> CreateAsync(UserDeviceCredentialDto userDeviceCredentialDto);

        Task<UserDeviceCredentialDto> GetSingleOrDefaultAsync(Func<UserDeviceCredentialDto, bool> func);
    }

    public class UserDeviceCredentialService : IUserDeviceCredentialService
    {
        private static readonly List<UserDeviceCredentialDto> Database = new List<UserDeviceCredentialDto>();

        static UserDeviceCredentialService()
        {
            var fullPath = Path.Combine(Directory.GetCurrentDirectory(), "public-rsa.json");

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

            var exponent = Convert.ToBase64String(rsaParameters.Exponent);
            var modulus = Convert.ToBase64String(rsaParameters.Modulus);

            Console.WriteLine(exponent);
            Console.WriteLine(modulus);

            Database.Add(
                new UserDeviceCredentialDto
                {
                    UserId = new Guid("fb4a6d23-e383-4b64-95f5-5b62601ac9cb"),
                    UserDeviceCredentialId = new Guid("12bf406a-ac37-43a2-8c5e-fcfc4bfa1f9f"),
                    DeviceId = new Guid("d1eaa073-0feb-48ad-bad2-0592963b4203"),
                    Exponent = exponent,
                    Modulus = modulus
                }
            );
        }

        public Task<UserDeviceCredentialDto> CreateAsync(UserDeviceCredentialDto userDeviceCredentialDto)
        {
            Database.Add(userDeviceCredentialDto);

            return Task.FromResult(userDeviceCredentialDto);
        }

        public Task<UserDeviceCredentialDto> GetSingleOrDefaultAsync(Func<UserDeviceCredentialDto, bool> func)
        {
            var userDeviceCredentialDto = Database.SingleOrDefault(func);
            return Task.FromResult(userDeviceCredentialDto);
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
}
