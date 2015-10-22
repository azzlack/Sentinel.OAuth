namespace Sentinel.Tests.Facade
{
    using Common.Logging;
    using Microsoft.Owin.Security.OAuth;
    using Microsoft.Owin.Testing;
    using Moq;
    using NUnit.Framework;
    using Owin;
    using Sentinel.OAuth.Core.Interfaces.Models;
    using Sentinel.OAuth.Core.Interfaces.Repositories;
    using Sentinel.OAuth.Core.Models;
    using Sentinel.OAuth.Core.Models.OAuth;
    using Sentinel.OAuth.Extensions;
    using Sentinel.OAuth.Implementation.Managers;
    using Sentinel.OAuth.Implementation.Providers;
    using Sentinel.OAuth.Implementation.Repositories;
    using Sentinel.Sample.Managers;
    using System.Collections.Generic;
    using System.Web.Http;

    [TestFixture]
    [Category("Facade")]
    public class SentinelTokenAuthorizationServerTests : AuthorizationServerTests
    {
        [TestFixtureSetUp]
        public override void TestFixtureSetUp()
        {
            this.Server = TestServer.Create(
                app =>
                    {
                        var cryptoProvider = new SHA2CryptoProvider();
                        var principalProvider = new PrincipalProvider(cryptoProvider);
                        var tokenRepository = new MemoryTokenRepository();
                        var clientRepository = new Mock<IClientRepository>();
                        clientRepository.Setup(x => x.GetClients()).ReturnsAsync(new List<IClient>() { new Client() { ClientId = "NUnit", ClientSecret = "aabbccddee", Enabled = true, RedirectUri = "http://localhost" } });
                        clientRepository.Setup(x => x.GetClient("NUnit")).ReturnsAsync(new Client() { ClientId = "NUnit", ClientSecret = "aabbccddee", Enabled = true, RedirectUri = "http://localhost" });
                        var tokenProvider = new SentinelTokenProvider(cryptoProvider, principalProvider);
                        var userManager = new SimpleUserManager();

                        app.UseSentinelAuthorizationServer(
                            new SentinelAuthorizationServerOptions()
                            {
                                ClientManager = new SimpleClientManager(),
                                UserManager = userManager,
                                TokenProvider = tokenProvider,
                                TokenManager = new TokenManager(LogManager.GetLogger<SentinelTokenAuthorizationServerTests>(), userManager, principalProvider, tokenProvider, tokenRepository, clientRepository.Object)
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