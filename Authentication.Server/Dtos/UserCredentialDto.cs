// ReSharper disable InconsistentNaming
namespace Authentication.Server.Dtos
{
    using System;

    public class CreateUserCredentialDto
    {
        public UserCredentialJwk Jwk { get; set; }

        public string UserId { get; set; }

        public DateTime? ExpirationDate { get; set; }

        public bool IsEnabled { get; set; }
    }

    public class UserCredentialDto : CreateUserCredentialDto
    {
        public string UserCredentialId { get; set; }
    }

    public class UserCredentialJwk
    {
        public string Kty { get; set; }
        public string Use { get; set; }
        public string Kid { get; set; }
        public string X5t { get; set; }
        public string E { get; set; }
        public string N { get; set; }
        public string[] X5c { get; set; }
        public string Alg { get; set; }
    }
}
