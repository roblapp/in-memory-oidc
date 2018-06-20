namespace Authentication.Server.Extensions
{
    using Authentication.Server.Filters;
    using Microsoft.Extensions.DependencyInjection;
    using Microsoft.Extensions.Logging;
    using Newtonsoft.Json;

    public static class MvcExtensions
    {
        public static void Configure(this IMvcBuilder mvcBuilder, ILoggerFactory loggerFactory)
        {
            mvcBuilder.AddMvcOptions(
                    options =>
                    {
                        options.Filters.Add(new GlobalExceptionFilter(loggerFactory));
                    })
                .AddJsonOptions(
                    options =>
                    {
                        var resolver = options.SerializerSettings;
                        resolver.NullValueHandling = NullValueHandling.Ignore;
                        resolver.ReferenceLoopHandling = ReferenceLoopHandling.Ignore;
                        // removes returning $id, $ref
                        resolver.PreserveReferencesHandling = PreserveReferencesHandling.None;
                        //Added 10/20/2017
                        resolver.DateFormatHandling = DateFormatHandling.IsoDateFormat;
                        resolver.Formatting = Formatting.Indented;
                    });
        }
    }
}
