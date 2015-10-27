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
    public class JwtAuthorizationServerTests : AuthorizationServerTests
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

            var clientRepository = new Mock<IClientRepository>();
            clientRepository.Setup(x => x.GetClient("NUnit")).ReturnsAsync(client);
            clientRepository.Setup(x => x.GetClients()).ReturnsAsync(new List<IClient>() { client });

            var userRepository = new Mock<IUserRepository>();
            userRepository.Setup(x => x.GetUser("azzlack")).ReturnsAsync(user);
            userRepository.Setup(x => x.GetUsers()).ReturnsAsync(new List<IUser>() { user });

            var cryptoProvider = new SHA2CryptoProvider(HashAlgorithm.SHA256);
            var issuerUri = new Uri("https://sentinel.oauth");

            this.SymmetricKey = cryptoProvider.CreateHash(256);

            this.Server = TestServer.Create(
                app =>
                    {
                        app.UseSentinelAuthorizationServer(new SentinelAuthorizationServerOptions()
                        {
                            ClientRepository = clientRepository.Object,
                            UserRepository = userRepository.Object,
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
            var accessTokenHash = new SHA2CryptoProvider(HashAlgorithm.SHA256).CreateHash(e.Item1.AccessToken, false);
            var digest = Convert.ToBase64String(Encoding.ASCII.GetBytes(accessTokenHash.ToCharArray(), 0, accessTokenHash.Length / 2));

            Assert.AreEqual(jwt.Payload.AccessTokenHash, digest);
        }
    }
}