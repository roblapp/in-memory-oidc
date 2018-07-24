// ReSharper disable InconsistentNaming
namespace Authentication.Server.Models
{
    using System;

    public class RFC7523RequestModel
    {
        public string Assertion { get; set; }
        public Guid KeyId { get; set; }
    }
}
