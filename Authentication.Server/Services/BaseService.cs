namespace Authentication.Server.Services
{
    using Microsoft.Extensions.Logging;

    public interface IBaseService
    {
    }

    public abstract class BaseService : IBaseService
    {
        protected BaseService(ILogger logger)
        {
            this.Logger = logger;
        }

        protected ILogger Logger { get; set; }
    }
}
