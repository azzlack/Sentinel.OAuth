namespace Sentinel.Tests.Facade
{
    using Microsoft.Owin.Security.OAuth;
    using Microsoft.Owin.Testing;
    using NUnit.Framework;
    using Owin;
    using Sentinel.OAuth.Core.Models;
    using Sentinel.OAuth.Extensions;
    using Sentinel.Sample.Managers;
    using System.Web.Http;

    [TestFixture]
    [Category("Facade")]
    public class JwtAuthorizationServerTests : AuthorizationServerTests
    {
        [TestFixtureSetUp]
        public override void TestFixtureSetUp()
        {
            this.Server = TestServer.Create(
                app =>
                {
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
                });

            base.TestFixtureSetUp();
        }
    }
}