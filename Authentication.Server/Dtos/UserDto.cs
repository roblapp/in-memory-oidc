namespace Authentication.Server.Dtos
{
    public class CreateUserDto
    {
        public string Username { get; set; }
        public string Email { get; set; }
        public string Password { get; set; }
        public string ProviderName { get; set; }
        public string ProviderSubjectId { get; set; }
        public bool IsActive { get; set; }
    }

    public class UserDto : CreateUserDto
    {
        public string UserId { get; set; }
    }
}
