// ReSharper disable InconsistentNaming
namespace Authentication.Server.Dtos
{
    using System;

    public class UserDeviceCredentialDto
    {
        public Guid UserDeviceCredentialId { get; set; }

        public Guid DeviceId { get; set; }

        public Guid UserId { get; set; }

        public string Exponent { get; set; }

        public string Modulus { get; set; }
    }
}
