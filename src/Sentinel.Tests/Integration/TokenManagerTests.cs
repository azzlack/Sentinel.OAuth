namespace Sentinel.Tests.Integration
{
    using System;
    using System.Collections.Generic;
    using System.Security.Claims;

    using Common.Logging;

    using NUnit.Framework;

    using Sentinel.OAuth.Core.Constants.Identity;
    using Sentinel.OAuth.Core.Interfaces.Managers;
    using Sentinel.OAuth.Extensions;
    using Sentinel.OAuth.Implementation;

    [TestFixture]
    [Category("Integration")]
    public class TokenManagerTests
    {
        private ITokenManager tokenManager;

        [SetUp]
        public void SetUp()
        {
            this.tokenManager = new TokenManager(LogManager.GetLogger<TokenManagerTests>(), new PrincipalProvider(), new PBKDF2CryptoProvider(), new MemoryTokenRepository());
        }

        [TestCase("NUnit", "http://localhost")]
        public async void AuthenticateAuthorizationCode_WhenGivenValidAuthorizationCode_ReturnsAuthenticatedPrincipal(string clientId, string redirectUri)
        {
            var a = this.CreateAuthenticatedPrincipal(clientId, AuthenticationType.OAuth);
            var t = await this.tokenManager.CreateAuthorizationCodeAsync(a, TimeSpan.FromMinutes(5), redirectUri);
            var r = await this.tokenManager.AuthenticateAuthorizationCodeAsync(redirectUri, t);

            Console.WriteLine("Identity: {0}", r.AsJson());

            Assert.IsTrue(r.Identity.IsAuthenticated);
            Assert.IsTrue(r.HasClaim(p => p.Type == ClaimTypes.AuthenticationMethod && p.Value == AuthenticationType.OAuth));
        }

        [TestCase("NUnit", "http://localhost")]
        public async void AuthenticateAuthorizationCode_WhenGivenInvalidAuthorizationCode_ReturnsNotAuthenticatedPrincipal(string clientId, string redirectUri)
        {
            var r = await this.tokenManager.AuthenticateAuthorizationCodeAsync(redirectUri, Guid.NewGuid().ToString("n"));

            Console.WriteLine("Identity: {0}", r.AsJson());

            Assert.IsFalse(r.Identity.IsAuthenticated);
        }

        [TestCase("NUnit", "http://localhost")]
        public async void AuthenticateRefreshToken_WhenGivenValidRefreshTokens_ReturnsAuthenticatedPrincipal(string clientId, string redirectUri)
        {
            var a = this.CreateAuthenticatedPrincipal(clientId, AuthenticationType.OAuth);
            var t = await this.tokenManager.CreateAuthorizationCodeAsync(a, TimeSpan.FromMinutes(5), redirectUri);
            var r = await this.tokenManager.AuthenticateAuthorizationCodeAsync(redirectUri, t);
            var y = await this.tokenManager.CreateRefreshTokenAsync(r, TimeSpan.FromMinutes(5), clientId, redirectUri);
            var x = await this.tokenManager.AuthenticateRefreshTokenAsync(clientId, y, redirectUri);

            Console.WriteLine("Client Id Identity: {0}", a.AsJson());
            Console.WriteLine("Authorization Code Identity: {0}", r.AsJson());
            Console.WriteLine("Refresh Token Identity: {0}", x.AsJson());

            Assert.IsTrue(x.Identity.IsAuthenticated);
            Assert.IsTrue(x.HasClaim(p => p.Type == ClaimTypes.AuthenticationMethod && p.Value == AuthenticationType.OAuth));
        }

        [TestCase("NUnit", "http://localhost")]
        public async void AuthenticateRefreshToken_WhenGivenInvalidRefreshToken_ReturnsNotAuthenticatedPrincipal(string clientId, string redirectUri)
        {
            var a = this.CreateAuthenticatedPrincipal(clientId, AuthenticationType.OAuth);
            var t = await this.tokenManager.CreateAuthorizationCodeAsync(a, TimeSpan.FromMinutes(5), redirectUri);
            var r = await this.tokenManager.AuthenticateAuthorizationCodeAsync(redirectUri, t);
            var y = await this.tokenManager.CreateRefreshTokenAsync(r, TimeSpan.FromMinutes(5), clientId, redirectUri);

            var tamperedToken = this.TamperWithToken(y);

            var x = await this.tokenManager.AuthenticateRefreshTokenAsync(clientId, tamperedToken, redirectUri);

            Console.WriteLine("Identity: {0}", x.AsJson());

            Assert.IsFalse(x.Identity.IsAuthenticated);
        }

        [TestCase("NUnit", "http://localhost")]
        public async void AuthenticateAccessToken_WhenGivenValidAccessTokens_ReturnsAuthenticatedPrincipal(string clientId, string redirectUri)
        {
            var a = this.CreateAuthenticatedPrincipal(clientId, AuthenticationType.OAuth);
            var t = await this.tokenManager.CreateAuthorizationCodeAsync(a, TimeSpan.FromMinutes(5), redirectUri);
            var r = await this.tokenManager.AuthenticateAuthorizationCodeAsync(redirectUri, t);
            var y = await this.tokenManager.CreateAccessTokenAsync(r, TimeSpan.FromHours(1), clientId, redirectUri);
            var x = await this.tokenManager.AuthenticateAccessTokenAsync(y);

            Console.WriteLine("Client Id Identity: {0}", a.AsJson());
            Console.WriteLine("Authorization Code Identity: {0}", r.AsJson());
            Console.WriteLine("Access Token Identity: {0}", x.AsJson());

            Assert.IsTrue(x.Identity.IsAuthenticated);
            Assert.IsTrue(x.HasClaim(p => p.Type == ClaimTypes.AuthenticationMethod && p.Value == AuthenticationType.OAuth));
        }

        [TestCase("NUnit", "http://localhost")]
        public async void AuthenticateAccessToken_WhenGivenInvalidAccessToken_ReturnsNotAuthenticatedPrincipal(string clientId, string redirectUri)
        {
            var a = this.CreateAuthenticatedPrincipal(clientId, AuthenticationType.OAuth);
            var t = await this.tokenManager.CreateAuthorizationCodeAsync(a, TimeSpan.FromMinutes(5), redirectUri);
            var r = await this.tokenManager.AuthenticateAuthorizationCodeAsync(redirectUri, t);
            var y = await this.tokenManager.CreateAccessTokenAsync(r, TimeSpan.FromHours(1), clientId, redirectUri);

            var tamperedToken = this.TamperWithToken(y);

            var x = await this.tokenManager.AuthenticateRefreshTokenAsync(clientId, tamperedToken, redirectUri);

            Console.WriteLine("Identity: {0}", x.AsJson());

            Assert.IsFalse(x.Identity.IsAuthenticated);
        }

        private ClaimsPrincipal CreateAuthenticatedPrincipal(string clientId, string authenticationType)
        {
            return new ClaimsPrincipal(new ClaimsIdentity(new List<Claim>() { new Claim(ClaimTypes.Name, "azzlack"), new Claim(ClaimType.Client, clientId) }, authenticationType));
        }

        private string TamperWithToken(string token)
        {
            var charArray = token.ToCharArray();
            Array.Reverse(charArray);

            return new string(charArray);
        }
    }
}