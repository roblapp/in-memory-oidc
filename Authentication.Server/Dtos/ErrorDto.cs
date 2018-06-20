namespace Authentication.Server.Dtos
{
    using System.Collections.Generic;

    public class ErrorDto
    {
        public ErrorDto()
        {
        }

        public ErrorDto(string message, int httpStatusCode, params string[] errors)
        {
            this.Message = message;
            this.HttpStatusCode = httpStatusCode;
            this.Errors = errors == null ? new List<string>() : new List<string>(errors);
        }

        public int HttpStatusCode { get; set; }

        public string Message { get; set; }

        public List<string> Errors { get; set; }
    }
}
