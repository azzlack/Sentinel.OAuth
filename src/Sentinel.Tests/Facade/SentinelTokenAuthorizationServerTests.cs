namespace Sentinel.Tests.Facade
{
    using System;

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
    using Sentinel.OAuth.Implementation.Providers;
    using System.Collections.Generic;
    using System.Web.Http;

    using Sentinel.OAuth.Core.Constants;

    [TestFixture]
    [Category("Facade")]
    public class SentinelTokenAuthorizationServerTests : BaseAuthorizationServerTests
    {
        [TestFixtureSetUp]
        public override void TestFixtureSetUp()
        {
            base.TestFixtureSetUp();

            var client = new Client()
            {
                ClientId = "NUnit",
                ClientSecret = this.PasswordCryptoProvider.CreateHash("PFJTQUtleVZhbHVlPjxNb2R1bHVzPnFKMEtXaXZWSjUxUWtKWGdIU1hidkxOTEJsa09rOE9uSWtvRTljU1FrRzhOZm5VYXBrWHpkTlEvb3FLZE9BSWxYK1hFMnNwN0xFcS9KRnJMaDRNblhRPT08L01vZHVsdXM+PEV4cG9uZW50PkFRQUI8L0V4cG9uZW50PjxQPnljRXBJUDJseG1oa0hRMGRrKzRBVk1lZDhWRUFFVHN5TXgvL3NaNS9TbFU9PC9QPjxRPjFmTEVGWU1JMk1TMUJQbzYwcnYyQmhkYWNBaTI2d2Z0V1N2OVl0aUdnT2s9PC9RPjxEUD5uZ0dYTW0wejdXVklNckJZMzhmZm5vWVBIalR2dG84RHk2SmQ0RDlmTlZrPTwvRFA+PERRPk5FZEQzclhNSFp2RFY5b0ZNYVU0TXJqV0luWWVyRU9kbmFLQUlmMGlzTEU9PC9EUT48SW52ZXJzZVE+ZGQzNVh6T0RvUlZQaXQxb2REL0lKRHpXdUtYMXZrb2NjcXQ4REZGVTlwVT08L0ludmVyc2VRPjxEPkFBcC80VW1oSmFJcm9DcWJ5eXdRbDViY0xFMXNSSkwxek50dllkdGxNTCsxWVFRdWx6YzVPRkh1WUcxQW56OE8vbXU2MXNDN0dNVm04ZTVqSUp6SldRPT08L0Q+PC9SU0FLZXlWYWx1ZT4="),
                //ClientSecret = "10000:gW7zpVeugKl8IFu7TcpPskcgQjy4185eAwBk9fFlZK6JNd1I45tLyCYtJrzWzE+kVCUP7lMSY8o808EjUgfavBzYU/ZtWypcdCdCJ0BMfMcf8Mk+XIYQCQLiFpt9Rjrf5mAY86NuveUtd1yBdPjxX5neMXEtquNYhu9I6iyzcN4=:Lk2ZkpmTDkNtO/tsB/GskMppdAX2bXehP+ED4oLis0AAv3Q1VeI8KL0SxIIWdxjKH0NJKZ6qniRFkfZKZRS2hS4SB8oyB34u/jyUlmv+RZGZSt9nJ9FYJn1percd/yFA7sSQOpkGljJ6OTwdthe0Bw0A/8qlKHbO2y2M5BFgYHY=",
                PublicKey = "PFJTQUtleVZhbHVlPjxNb2R1bHVzPnFKMEtXaXZWSjUxUWtKWGdIU1hidkxOTEJsa09rOE9uSWtvRTljU1FrRzhOZm5VYXBrWHpkTlEvb3FLZE9BSWxYK1hFMnNwN0xFcS9KRnJMaDRNblhRPT08L01vZHVsdXM+PEV4cG9uZW50PkFRQUI8L0V4cG9uZW50PjwvUlNBS2V5VmFsdWU+",
                RedirectUri = "http://localhost",
                Enabled = true
            };
            var user = new User()
            {
                UserId = "azzlack",
                Password = this.PasswordCryptoProvider.CreateHash("aabbccddee"),
                //Password = "10000:gW7zpVeugKl8IFu7TcpPskcgQjy4185eAwBk9fFlZK6JNd1I45tLyCYtJrzWzE+kVCUP7lMSY8o808EjUgfavBzYU/ZtWypcdCdCJ0BMfMcf8Mk+XIYQCQLiFpt9Rjrf5mAY86NuveUtd1yBdPjxX5neMXEtquNYhu9I6iyzcN4=:Lk2ZkpmTDkNtO/tsB/GskMppdAX2bXehP+ED4oLis0AAv3Q1VeI8KL0SxIIWdxjKH0NJKZ6qniRFkfZKZRS2hS4SB8oyB34u/jyUlmv+RZGZSt9nJ9FYJn1percd/yFA7sSQOpkGljJ6OTwdthe0Bw0A/8qlKHbO2y2M5BFgYHY=",
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

            this.Server = TestServer.Create(
                app =>
                    {
                        var principalProvider = new PrincipalProvider(new SHA2CryptoProvider(HashAlgorithm.SHA512));
                        var tokenProvider = new SentinelTokenProvider(new SHA2CryptoProvider(HashAlgorithm.SHA512), principalProvider);

                        app.UseSentinelAuthorizationServer(
                            new SentinelAuthorizationServerOptions()
                            {
                                RequireSecureConnection = false,
                                EnableBasicAuthentication = true,
                                EnableSignatureAuthentication = true,
                                ClientRepository = clientRepository.Object,
                                UserRepository = userRepository.Object,
                                UserApiKeyRepository = userApiKeyRepository.Object,
                                TokenProvider = tokenProvider,
                                IssuerUri = new Uri("https://sentinel.oauth")
                            });

                        // Start up web api
                        var httpConfig = new HttpConfiguration();
                        httpConfig.MapHttpAttributeRoutes();

                        // Configure Web API to use only Bearer token authentication.
                        httpConfig.Filters.Add(new HostAuthenticationFilter(OAuthDefaults.AuthenticationType));

                        httpConfig.EnsureInitialized();

                        app.UseWebApi(httpConfig);
                    });
        }
    }
}