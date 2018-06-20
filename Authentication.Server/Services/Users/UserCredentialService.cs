namespace Authentication.Server.Services.Users
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Threading.Tasks;
    using Authentication.Server.Dtos;

    public interface IUserCredentialService
    {
        Task<UserCredentialDto> CreateAsync(CreateUserCredentialDto createDto);

        Task<UserCredentialDto> GetSingleOrDefaultAsync(Func<UserCredentialDto, bool> func);

        Task<List<UserCredentialDto>> GetManyAsync(Func<UserCredentialDto, bool> func);
    }

    public class UserCredentialService : IUserCredentialService
    {
        private static readonly List<UserCredentialDto> Database = new List<UserCredentialDto>();

        public Task<UserCredentialDto> CreateAsync(CreateUserCredentialDto createDto)
        {
            var userCredential = new UserCredentialDto
                                 {
                                     UserCredentialId = Guid.NewGuid().ToString(),
                                     ExpirationDate = createDto.ExpirationDate,
                                     IsEnabled = createDto.IsEnabled,
                                     Jwk = createDto.Jwk,
                                     UserId = createDto.UserId
                                 };

            Database.Add(userCredential);

            return Task.FromResult(userCredential);
        }

        public Task<UserCredentialDto> GetSingleOrDefaultAsync(Func<UserCredentialDto, bool> func)
        {
            var userCredential = Database.SingleOrDefault(func);
            return Task.FromResult(userCredential);
        }

        public Task<List<UserCredentialDto>> GetManyAsync(Func<UserCredentialDto, bool> func)
        {
            var userCredentials = Database.Where(func);
            return Task.FromResult(userCredentials.ToList());
        }
    }
}
