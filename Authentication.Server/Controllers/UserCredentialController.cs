namespace Authentication.Server.Controllers
{
    using System;
    using System.Threading.Tasks;
    using Authentication.Server.Dtos;
    using Authentication.Server.Services.Users;
    using Microsoft.AspNetCore.Mvc;
    
    [Route("api/v1/[controller]")]
    public class UserCredentialController : Controller
    {
        private readonly IUserCredentialService userCredentialService;

        public UserCredentialController(IUserCredentialService userCredentialService)
        {
            this.userCredentialService = userCredentialService;
        }


        public async Task<IActionResult> CreateUserCredentialAsync(CreateUserCredentialDto createUserCredentialDto)
        {
            var result = await this.userCredentialService.CreateAsync(createUserCredentialDto);

            return this.CreatedAtAction(nameof(this.GetUserCredentialByIdAsync), new { userCredentialId  = result.UserCredentialId }, result);
        }

        [HttpGet("credentials/{userCredentialId}")]
        public async Task<IActionResult> GetUserCredentialByIdAsync(string userCredentialId)
        {
            var result = await this.userCredentialService.GetSingleOrDefaultAsync(
                x => string.Equals(x.UserCredentialId, userCredentialId, StringComparison.InvariantCultureIgnoreCase));

            return this.Json(result);
        }

        [HttpGet("users/{userId}")]
        public async Task<IActionResult> GetUserCredentialByUserIdAsync(string userId)
        {
            var result = await this.userCredentialService.GetSingleOrDefaultAsync(
                x => string.Equals(x.UserId, userId, StringComparison.InvariantCultureIgnoreCase));

            return this.Json(result);
        }
    }
}
