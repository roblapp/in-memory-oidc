namespace Authentication.Server.Filters
{
    using System.Collections.Generic;
    using System.Linq;
    using System.Net;
    using System.Security.Authentication;
    using Authentication.Server.Dtos;
    using Microsoft.AspNetCore.Mvc;
    using Microsoft.AspNetCore.Mvc.Filters;
    using Microsoft.Extensions.Logging;

    //https://docs.microsoft.com/en-us/aspnet/core/fundamentals/error-handling
    public class GlobalExceptionFilter : ExceptionFilterAttribute
    {
        private readonly ILogger logger;

        public GlobalExceptionFilter(ILoggerFactory loggerFactory)
        {
            this.logger = loggerFactory.CreateLogger(typeof(GlobalExceptionFilter));
        }

        /// <inheritdoc />
        public override void OnException(ExceptionContext context)
        {
            var exception = context.Exception;
            HttpStatusCode statusCode;
            var errorMessages = new List<string> { exception.Message };

            this.logger.LogError("An exception has been thrown!", exception);
            this.logger.LogError(exception.Message);

            if (!string.IsNullOrWhiteSpace(exception.InnerException?.Message))
            {
                this.logger.LogError(exception.InnerException.Message);
                errorMessages.Add(exception.InnerException.Message);
            }

            if (exception is AuthenticationException)
            {
                this.logger.LogError("The Exception type is AuthenticationException. An 401 is being issued");
                statusCode = HttpStatusCode.Unauthorized;
            }
            else
            {
                this.logger.LogError("The Exception type will be treated as a bad request. A 400 is being issued");
                statusCode = HttpStatusCode.BadRequest;
            }

            var errorMessagesArray = errorMessages.Any() ? null : errorMessages.ToArray();
            var errorDto = new ErrorDto(exception.Message, (int)statusCode, errorMessagesArray);

            context.Result = new JsonResult(errorDto)
                             {
                                 StatusCode = (int)statusCode,
                                 ContentType = "application/json"
                             };

            context.ExceptionHandled = true;
        }
    }
}
