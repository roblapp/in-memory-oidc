// ReSharper disable RedundantTypeArgumentsOfMethod
namespace Authentication.Server
{
    using Authentication.Server.Extensions;
    using Authentication.Server.IdentityServer;
    using Authentication.Server.Services;
    using Authentication.Server.Services.Login;
    using Authentication.Server.Services.Users;
    using Authentication.Server.Services.ViewServices;
    using Authentication.Server.Validation;
    using IdentityServer4;
    using IdentityServer4.Validation;
    using Microsoft.AspNetCore.Builder;
    using Microsoft.AspNetCore.Hosting;
    using Microsoft.Extensions.Configuration;
    using Microsoft.Extensions.DependencyInjection;
    using Microsoft.Extensions.Logging;

    public class Startup
    {
        private readonly ILoggerFactory loggerFactory;
        private readonly IConfiguration configuration;

        public Startup(ILoggerFactory loggerFactory, IConfiguration configuration)
        {
            this.loggerFactory = loggerFactory;
            this.configuration = configuration;
        }

        // This method gets called by the runtime. Use this method to add services to the container.
        // For more information on how to configure your application, visit https://go.microsoft.com/fwlink/?LinkID=398940
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddSingleton<IConfiguration>(this.configuration);
            services.AddSingleton<IUserService>(new UserService());
            services.AddTransient<ILocalLoginService, LocalLoginService>();
            services.AddTransient<IExternalLoginService, ExternalLoginService>();
            services.AddTransient<IAccountViewService, AccountViewService>();
            services.AddTransient<IConsentViewService, ConsentViewService>();
            services.AddTransient<IExtensionGrantValidator, RFC7523GrantValidator>();
            services.AddTransient<IRFC7523RequestParser, RFC7523RequestParser>();
            services.AddTransient<IUserDeviceCredentialService, UserDeviceCredentialService>();

            services.AddMvc().Configure(this.loggerFactory);

            services.AddIdentityServer().Configure();

            services.AddAuthentication()
                .AddGoogle(
                    "Google",
                    googleOptions =>
                    {
                        googleOptions.SignInScheme = IdentityServerConstants.ExternalCookieAuthenticationScheme;
                        googleOptions.ClientId = "599100066788-vhujnjcj8n79ngjdeme92av1p2o3c1r1.apps.googleusercontent.com";
                        googleOptions.ClientSecret = "UeHF1MHK8Z8agXpm32qrA1ZA";
                    });
            //.AddJwtBearer(
            //    jwtBearerOptions =>
            //    {
            //        jwtBearerOptions.Authority = "http://localhost:5000";
            //        jwtBearerOptions.SaveToken = true;
            //        jwtBearerOptions.RequireHttpsMetadata = false;
            //    });

            Microsoft.IdentityModel.Logging.IdentityModelEventSource.ShowPII = true;
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment hostingEnvironment)
        {
            if (hostingEnvironment.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("Home/Error");
            }

            app.UseIdentityServer();
            app.UseStaticFiles();
            app.UseMvcWithDefaultRoute();
        }
    }
}
