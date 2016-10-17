using Microsoft.Owin;

using Sentinel.Sample;

[assembly: OwinStartup(typeof(Startup))]

namespace Sentinel.Sample
{
    using System;
    using System.Configuration;
    using System.Web.Http;
    using System.Web.Mvc;
    using System.Web.Routing;

    using Common.Logging;

    using log4net.Config;

    using Microsoft.AspNet.Identity;
    using Microsoft.Owin.Infrastructure;
    using Microsoft.Owin.Security.Cookies;
    using Microsoft.Owin.Security.OAuth;

    using Owin;

    using Sentinel.OAuth.Core.Models;
    using Sentinel.OAuth.Extensions;
    using Sentinel.OAuth.Implementation.Providers;
    using Sentinel.Sample.Managers;

    public class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            // Configure log4net
            XmlConfigurator.Configure();

            var apiUrl = new Uri(ConfigurationManager.AppSettings["ApiUrl"]);

            // Set up cookie authentication
            app.UseCookieAuthentication(
                    new CookieAuthenticationOptions()
                    {
                        AuthenticationType = DefaultAuthenticationTypes.ApplicationCookie,
                        CookieDomain = apiUrl.Host,
                        CookieName = "SENTINEL_AUTH",
                        LoginPath = new PathString("/authentication/login"),
                        LogoutPath = new PathString("/authentication/logout")
                    });

            // The easiest way to use Sentinel
            app.UseSentinelAuthorizationServer(
                new SentinelAuthorizationServerOptions()
                    {
                        IssuerUri = apiUrl,
                        ClientManager = new SimpleClientManager(),
                        UserManager = new SimpleUserManager(new PBKDF2CryptoProvider(), new AsymmetricCryptoProvider())
                    });

            // Start up web api
            var httpConfig = new HttpConfiguration();
            httpConfig.MapHttpAttributeRoutes();

            // Configure Web API to use only Bearer token authentication.
            httpConfig.Filters.Add(new HostAuthenticationFilter(OAuthDefaults.AuthenticationType));

            httpConfig.EnsureInitialized();

            app.UseWebApi(httpConfig);

            // Configure mvc
            AreaRegistration.RegisterAllAreas(httpConfig);
            GlobalFilters.Filters.Add(new HandleErrorAttribute());
            RouteTable.Routes.IgnoreRoute("{resource}.axd/{*pathInfo}");
            RouteTable.Routes.MapMvcAttributeRoutes();
            RouteTable.Routes.MapRoute(name: "Default", url: "{controller}/{action}/{id}", defaults: new { controller = "Home", action = "Index", id = UrlParameter.Optional });

            LogManager.GetLogger<Startup>().Info("Application started");
        }
    }
}
