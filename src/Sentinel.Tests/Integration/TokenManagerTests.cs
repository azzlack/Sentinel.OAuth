namespace Sentinel.Tests.Integration
{
    using Common.Logging;
    using Moq;
    using NUnit.Framework;
    using Sentinel.OAuth.Core.Constants.Identity;
    using Sentinel.OAuth.Core.Interfaces.Identity;
    using Sentinel.OAuth.Core.Interfaces.Managers;
    using Sentinel.OAuth.Core.Interfaces.Models;
    using Sentinel.OAuth.Core.Interfaces.Repositories;
    using Sentinel.OAuth.Core.Models.OAuth;
    using Sentinel.OAuth.Extensions;
    using Sentinel.OAuth.Implementation.Managers;
    using Sentinel.OAuth.Implementation.Providers;
    using Sentinel.OAuth.Implementation.Repositories;
    using Sentinel.OAuth.Models.Identity;
    using Sentinel.Tests.Constants;
    using System;
    using System.Collections.Generic;
    using System.Security.Claims;

    [TestFixture]
    [Category("Integration")]
    public class TokenManagerTests
    {
        private ITokenManager tokenManager;

        [SetUp]
        public void SetUp()
        {
            var userManager = new Mock<IUserManager>();
            userManager.Setup(x => x.AuthenticateUserAsync(It.IsAny<string>()))
                .ReturnsAsync(new SentinelPrincipal(
                        new SentinelIdentity(
                            AuthenticationType.OAuth,
                            new SentinelClaim(ClaimTypes.Name, "azzlack"),
                            new SentinelClaim(ClaimType.Client, "NUnit"))));

            var principalProvider = new PrincipalProvider(new PBKDF2CryptoProvider());
            var tokenRepository = new MemoryTokenRepository();
            var clientRepository = new Mock<IClientRepository>();
            clientRepository.Setup(x => x.GetClients())
                .ReturnsAsync(
                    new List<IClient>()
                        {
                            new Client()
                                {
                                    ClientId = "NUnit",
                                    ClientSecret = "aabbccddee",
                                    RedirectUri = "http://localhost"
                                }
                        });

            this.tokenManager = new TokenManager(
                LogManager.GetLogger<TokenManagerTests>(),
                userManager.Object,
                principalProvider,
                new SentinelTokenProvider(new SHA2CryptoProvider(), principalProvider),
                tokenRepository,
                clientRepository.Object);
        }

        [TestCase("NUnit", "http://localhost")]
        public async void AuthenticateAuthorizationCode_WhenGivenValidAuthorizationCode_ReturnsAuthenticatedPrincipal(string clientId, string redirectUri)
        {
            var a = this.CreateAuthenticatedPrincipal(clientId, AuthenticationType.OAuth);
            var t = await this.tokenManager.CreateAuthorizationCodeAsync(a, TimeSpan.FromMinutes(5), redirectUri, null);
            var r = await this.tokenManager.AuthenticateAuthorizationCodeAsync(redirectUri, t);

            Console.WriteLine("Authorization Code: {0}", t);
            Console.WriteLine();
            Console.WriteLine("Identity: {0}", r.ToJson());

            Assert.IsTrue(r.Identity.IsAuthenticated);
            Assert.IsTrue(r.Identity.AuthenticationType == AuthenticationType.OAuth);
        }

        [TestCase("NUnit", "http://localhost")]
        public async void AuthenticateAuthorizationCode_WhenGivenInvalidAuthorizationCode_ReturnsNotAuthenticatedPrincipal(string clientId, string redirectUri)
        {
            var r = await this.tokenManager.AuthenticateAuthorizationCodeAsync(redirectUri, Guid.NewGuid().ToString("n"));

            Console.WriteLine("Identity: {0}", r.ToJson());

            Assert.IsFalse(r.Identity.IsAuthenticated);
        }

        [TestCase("NUnit", "http://localhost")]
        public async void AuthenticateRefreshToken_WhenGivenValidRefreshTokens_ReturnsAuthenticatedPrincipal(string clientId, string redirectUri)
        {
            var a = this.CreateAuthenticatedPrincipal(clientId, AuthenticationType.OAuth);
            var t = await this.tokenManager.CreateAuthorizationCodeAsync(a, TimeSpan.FromMinutes(5), redirectUri, new[] { Scope.Read });
            var r = await this.tokenManager.AuthenticateAuthorizationCodeAsync(redirectUri, t);
            var y = await this.tokenManager.CreateRefreshTokenAsync(r, TimeSpan.FromMinutes(5), clientId, redirectUri, new[] { Scope.Read });
            var x = await this.tokenManager.AuthenticateRefreshTokenAsync(clientId, y, redirectUri);

            Console.WriteLine("Authorization Code: {0}", t);
            Console.WriteLine("Refresh Token: {0}", y);
            Console.WriteLine();
            Console.WriteLine("Client Id Identity: {0}", a.ToJson());
            Console.WriteLine();
            Console.WriteLine("Authorization Code Identity: {0}", r.ToJson());
            Console.WriteLine();
            Console.WriteLine("Refresh Token Identity: {0}", x.ToJson());

            Assert.IsTrue(x.Identity.IsAuthenticated);
            Assert.IsTrue(x.Identity.AuthenticationType == AuthenticationType.OAuth);
        }

        [TestCase("NUnit", "http://localhost")]
        public async void AuthenticateRefreshToken_WhenGivenInvalidRefreshToken_ReturnsNotAuthenticatedPrincipal(string clientId, string redirectUri)
        {
            var a = this.CreateAuthenticatedPrincipal(clientId, AuthenticationType.OAuth);
            var t = await this.tokenManager.CreateAuthorizationCodeAsync(a, TimeSpan.FromMinutes(5), redirectUri, new[] { Scope.Read });
            var r = await this.tokenManager.AuthenticateAuthorizationCodeAsync(redirectUri, t);
            var y = await this.tokenManager.CreateRefreshTokenAsync(r, TimeSpan.FromMinutes(5), clientId, redirectUri, new[] { Scope.Read });

            var tamperedToken = this.TamperWithToken(y);

            var x = await this.tokenManager.AuthenticateRefreshTokenAsync(clientId, tamperedToken, redirectUri);

            Console.WriteLine("Identity: {0}", x.ToJson());

            Assert.IsFalse(x.Identity.IsAuthenticated);
        }

        [TestCase("NUnit", "http://localhost")]
        public async void AuthenticateAccessToken_WhenGivenValidAccessTokens_ReturnsAuthenticatedPrincipal(string clientId, string redirectUri)
        {
            var a = this.CreateAuthenticatedPrincipal(clientId, AuthenticationType.OAuth);
            var t = await this.tokenManager.CreateAuthorizationCodeAsync(a, TimeSpan.FromMinutes(5), redirectUri, new[] { Scope.Read });
            var r = await this.tokenManager.AuthenticateAuthorizationCodeAsync(redirectUri, t);
            var y = await this.tokenManager.CreateAccessTokenAsync(r, TimeSpan.FromHours(1), clientId, redirectUri, new[] { Scope.Read });
            var x = await this.tokenManager.AuthenticateAccessTokenAsync(y);

            Console.WriteLine("Authorization Code: {0}", t);
            Console.WriteLine("Access Token: {0}", y);
            Console.WriteLine();
            Console.WriteLine("Client Id Identity: {0}", a.ToJson());
            Console.WriteLine();
            Console.WriteLine("Authorization Code Identity: {0}", r.ToJson());
            Console.WriteLine();
            Console.WriteLine("Access Token Identity: {0}", x.ToJson());

            Assert.IsTrue(x.Identity.IsAuthenticated);
            Assert.IsTrue(x.Identity.AuthenticationType == AuthenticationType.OAuth);
        }

        [TestCase("NUnit", "http://localhost")]
        public async void AuthenticateAccessToken_WhenGivenInvalidAccessToken_ReturnsNotAuthenticatedPrincipal(string clientId, string redirectUri)
        {
            var a = this.CreateAuthenticatedPrincipal(clientId, AuthenticationType.OAuth);
            var t = await this.tokenManager.CreateAuthorizationCodeAsync(a, TimeSpan.FromMinutes(5), redirectUri, new[] { Scope.Read });
            var r = await this.tokenManager.AuthenticateAuthorizationCodeAsync(redirectUri, t);
            var y = await this.tokenManager.CreateAccessTokenAsync(r, TimeSpan.FromHours(1), clientId, redirectUri, new[] { Scope.Read });

            var tamperedToken = this.TamperWithToken(y);

            var x = await this.tokenManager.AuthenticateRefreshTokenAsync(clientId, tamperedToken, redirectUri);

            Console.WriteLine("Identity: {0}", x.ToJson());

            Assert.IsFalse(x.Identity.IsAuthenticated);
        }

        private ISentinelPrincipal CreateAuthenticatedPrincipal(string clientId, string authenticationType)
        {
            return new SentinelPrincipal(new SentinelIdentity(authenticationType, new SentinelClaim(ClaimTypes.Name, "azzlack"), new SentinelClaim(ClaimType.Client, clientId)));
        }

        private string TamperWithToken(string token)
        {
            var charArray = token.ToCharArray();
            Array.Reverse(charArray);

            return new string(charArray);
        }
    }
}