// ReSharper disable UseNullPropagation
namespace Authentication.Api
{
    using System.IdentityModel.Tokens.Jwt;
    using Microsoft.AspNetCore.Authentication.JwtBearer;
    using Microsoft.AspNetCore.Builder;
    using Microsoft.AspNetCore.Hosting;
    using Microsoft.Extensions.DependencyInjection;
    using Microsoft.Extensions.Logging;

    public class Startup
    {
        // This method gets called by the runtime. Use this method to add services to the container.
        // For more information on how to configure your application, visit https://go.microsoft.com/fwlink/?LinkID=398940
        public void ConfigureServices(IServiceCollection services)
        {
            services
                .AddMvcCore()
                .AddJsonFormatters()
                .AddAuthorization();

            //If this isn't done then the claims will be mapped to Microsoft claim types => NOT the claim types as they were issued by the OIDC provider
            JwtSecurityTokenHandler.DefaultInboundClaimTypeMap.Clear();

            services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
                .AddJwtBearer(
                    options =>
                    {
                        options.Authority = "http://localhost:5000";
                        options.SaveToken = true;
                        options.RequireHttpsMetadata = false;
                        options.IncludeErrorDetails = true;
                        options.Audience = "api.resource"; //Matches an ApiResource defined in the authentication service. The ApiResource models this API
                    });

            services.AddCors(options =>
            {
                // this defines a CORS policy called "defaultCorsPolicy"
                options.AddPolicy("defaultCorsPolicy", policy =>
                {
                    policy
                        .AllowAnyOrigin()
                        .AllowAnyHeader()
                        .AllowAnyMethod();
                });
            });
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env, ILoggerFactory loggerFactory)
        {
            app.UseCors("defaultCorsPolicy");
            app.UseAuthentication();
            app.UseMvc();
        }
    }
}

