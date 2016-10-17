namespace Sentinel.Tests.Facade
{
    using Microsoft.Owin.Security.OAuth;
    using Microsoft.Owin.Testing;
    using Moq;
    using NUnit.Framework;
    using Owin;
    using Sentinel.OAuth.Core.Constants;
    using Sentinel.OAuth.Core.Interfaces.Models;
    using Sentinel.OAuth.Core.Interfaces.Repositories;
    using Sentinel.OAuth.Core.Models;
    using Sentinel.OAuth.Core.Models.OAuth;
    using Sentinel.OAuth.Core.Models.OAuth.Http;
    using Sentinel.OAuth.Core.Models.Tokens;
    using Sentinel.OAuth.Extensions;
    using Sentinel.OAuth.Implementation.Providers;
    using Sentinel.OAuth.Models.Providers;
    using System;
    using System.Collections.Generic;
    using System.Text;
    using System.Web.Http;

    [TestFixture]
    [Category("Facade")]
    public class JwtAuthorizationServerTests : BaseAuthorizationServerTests
    {
        public JwtAuthorizationServerTests()
        {
            this.ValidateTokenEventHandler += this.OnValidateToken;
        }

        [TestFixtureSetUp]
        public override void TestFixtureSetUp()
        {
            var client = new Client()
            {
                ClientId = "NUnit",
                ClientSecret = "10000:gW7zpVeugKl8IFu7TcpPskcgQjy4185eAwBk9fFlZK6JNd1I45tLyCYtJrzWzE+kVCUP7lMSY8o808EjUgfavBzYU/ZtWypcdCdCJ0BMfMcf8Mk+XIYQCQLiFpt9Rjrf5mAY86NuveUtd1yBdPjxX5neMXEtquNYhu9I6iyzcN4=:Lk2ZkpmTDkNtO/tsB/GskMppdAX2bXehP+ED4oLis0AAv3Q1VeI8KL0SxIIWdxjKH0NJKZ6qniRFkfZKZRS2hS4SB8oyB34u/jyUlmv+RZGZSt9nJ9FYJn1percd/yFA7sSQOpkGljJ6OTwdthe0Bw0A/8qlKHbO2y2M5BFgYHY=",
                PublicKey = "PFJTQUtleVZhbHVlPjxNb2R1bHVzPnFKMEtXaXZWSjUxUWtKWGdIU1hidkxOTEJsa09rOE9uSWtvRTljU1FrRzhOZm5VYXBrWHpkTlEvb3FLZE9BSWxYK1hFMnNwN0xFcS9KRnJMaDRNblhRPT08L01vZHVsdXM+PEV4cG9uZW50PkFRQUI8L0V4cG9uZW50PjwvUlNBS2V5VmFsdWU+",
                RedirectUri = "http://localhost",
                Enabled = true
            };
            var user = new User()
            {
                UserId = "azzlack",
                Password = "10000:gW7zpVeugKl8IFu7TcpPskcgQjy4185eAwBk9fFlZK6JNd1I45tLyCYtJrzWzE+kVCUP7lMSY8o808EjUgfavBzYU/ZtWypcdCdCJ0BMfMcf8Mk+XIYQCQLiFpt9Rjrf5mAY86NuveUtd1yBdPjxX5neMXEtquNYhu9I6iyzcN4=:Lk2ZkpmTDkNtO/tsB/GskMppdAX2bXehP+ED4oLis0AAv3Q1VeI8KL0SxIIWdxjKH0NJKZ6qniRFkfZKZRS2hS4SB8oyB34u/jyUlmv+RZGZSt9nJ9FYJn1percd/yFA7sSQOpkGljJ6OTwdthe0Bw0A/8qlKHbO2y2M5BFgYHY=",
                FirstName = "Ove",
                LastName = "Andersen",
                Enabled = true
            };
            var userApiKeys = new List<IUserApiKey>()
                                  {
                                      new UserApiKey() { UserId = "azzlack", ApiKey = "PFJTQUtleVZhbHVlPjxNb2R1bHVzPnlidFpyM0pWS0p1L2hlUFMrV0Zla1kyYmRYVDlJMU1MeHZheTlIMW9IenRwRmI4QzJtQmUzY1EzVDhjUzE0ajJ4bk9lRkt2YVZ4Ukw5S2ozd0tOL1B3PT08L01vZHVsdXM+PEV4cG9uZW50PkFRQUI8L0V4cG9uZW50PjwvUlNBS2V5VmFsdWU+" }
                                  };

            var clientRepository = new Mock<IClientRepository>();
            clientRepository.Setup(x => x.GetClient("NUnit")).ReturnsAsync(client);
            clientRepository.Setup(x => x.GetClients()).ReturnsAsync(new List<IClient>() { client });

            var userRepository = new Mock<IUserRepository>();
            userRepository.Setup(x => x.GetUser("azzlack")).ReturnsAsync(user);
            userRepository.Setup(x => x.GetUsers()).ReturnsAsync(new List<IUser>() { user });

            var userApiKeyRepository = new Mock<IUserApiKeyRepository>();
            userApiKeyRepository.Setup(x => x.GetForUser("azzlack")).ReturnsAsync(userApiKeys);

            var cryptoProvider = new SHA2CryptoProvider(HashAlgorithm.SHA256);
            var issuerUri = new Uri("https://sentinel.oauth");

            this.SymmetricKey = cryptoProvider.CreateHash(256);

            this.Server = TestServer.Create(
                app =>
                    {
                        app.UseSentinelAuthorizationServer(new SentinelAuthorizationServerOptions()
                        {
                            RequireSecureConnection = false,
                            EnableBasicAuthentication = true,
                            EnableSignatureAuthentication = true,
                            ClientRepository = clientRepository.Object,
                            UserRepository = userRepository.Object,
                            UserApiKeyRepository = userApiKeyRepository.Object,
                            IssuerUri = issuerUri,
                            TokenProvider = new JwtTokenProvider(new JwtTokenProviderConfiguration(cryptoProvider, issuerUri, this.SymmetricKey))
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

        /// <summary>Executes the validate token action.</summary>
        /// <param name="sender">Source of the event.</param>
        /// <param name="e">The Tuple&lt;AccessTokenResponse,IdentityResponse&gt; to process.</param>
        private void OnValidateToken(object sender, Tuple<AccessTokenResponse, IdentityResponse> e)
        {
            // Decode id_token
            var jwt = new JsonWebToken(e.Item1.IdToken);

            Assert.IsNotNull(jwt);

            Console.WriteLine();
            Console.WriteLine("ID Token Claims");

            foreach (var claim in jwt.Payload)
            {
                Console.WriteLine("{0}: {1}", claim.Key, claim.Value);
            }

            // Validate at_hash
            Assert.IsTrue(jwt.ValidateAccessToken(e.Item1.AccessToken));
        }
    }
}