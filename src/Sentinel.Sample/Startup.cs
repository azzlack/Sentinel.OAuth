using Microsoft.Owin;

using Sentinel.Sample;

[assembly: OwinStartup(typeof(Startup))]

namespace Sentinel.Sample
{
    using System.Web.Http;

    using Common.Logging;

    using log4net.Config;

    using Microsoft.Owin.Security.OAuth;

    using Owin;

    using Sentinel.OAuth.Core.Models;
    using Sentinel.OAuth.Extensions;
    using Sentinel.Sample.Managers;

    public class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            // Configure log4net
            XmlConfigurator.Configure();

            // The easiest way to use Sentinel
            app.UseSentinelAuthorizationServer(new SentinelAuthorizationServerOptions()
                                                   {
                                                       ClientManager = new SimpleClientManager(),
                                                       UserManager = new SimpleUserManager()
                                                   });

            // Start up web api
            var httpConfig = new HttpConfiguration();
            httpConfig.MapHttpAttributeRoutes();

            // Configure Web API to use only Bearer token authentication.
            httpConfig.Filters.Add(new HostAuthenticationFilter(OAuthDefaults.AuthenticationType));

            httpConfig.EnsureInitialized();

            app.UseWebApi(httpConfig);

            LogManager.GetLogger<Startup>().Info("Application started");
        }
    }
}
