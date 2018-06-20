namespace Authentication.Server.Services.Users
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Threading.Tasks;
    using Authentication.Server.Dtos;
    using Authentication.Server.IdentityServer;

    public interface IUserService
    {
        Task<UserDto> CreateAsync(UserDto createDto);

        Task<UserDto> GetSingleOrDefaultAsync(Func<UserDto, bool> func);
    }

    public class UserService : IUserService
    {
        private static readonly List<UserDto> Database = new List<UserDto>();

        static UserService()
        {
            var users = InMemoryResources.GetUsers();

            foreach (var user in users)
            {
                Database.Add(user);
            }
        }

        public Task<UserDto> CreateAsync(UserDto createDto)
        {
            Database.Add(createDto);

            return Task.FromResult(createDto);
        }

        public Task<UserDto> GetSingleOrDefaultAsync(Func<UserDto, bool> func)
        {
            var user = Database.SingleOrDefault(func);
            return Task.FromResult(user);
        }
    }
}
