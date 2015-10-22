namespace Sentinel.Tests.Integration.TokenProviders
{
    using Moq;
    using NUnit.Framework;
    using Sentinel.OAuth.Core.Constants.Identity;
    using Sentinel.OAuth.Core.Interfaces.Models;
    using Sentinel.OAuth.Core.Interfaces.Providers;
    using Sentinel.OAuth.Core.Interfaces.Repositories;
    using Sentinel.OAuth.Core.Models.OAuth;
    using Sentinel.OAuth.Models.Identity;
    using System;
    using System.Collections.Generic;
    using System.Diagnostics;
    using System.Security.Claims;
    using System.Text;

    public abstract class TokenProviderTests
    {
        private Stopwatch testFixtureStopwatch;

        private Stopwatch testStopwatch;

        public ITokenProvider TokenProvider { get; set; }

        public ITokenRepository TokenRepository { get; set; }

        [TestFixtureSetUp]
        public virtual void TestFixtureSetUp()
        {
            var tokenRepository = new Mock<ITokenRepository>();
            tokenRepository.Setup(x => x.GetAuthorizationCodes(It.IsAny<string>(), It.IsAny<DateTimeOffset>()))
                .ReturnsAsync(
                    new List<IAuthorizationCode>()
                        {
                            new AuthorizationCode()
                                {
                                    ClientId = "NUnit",
                                    RedirectUri = "http://localhost",
                                    Subject = "ovea"
                                }
                        });
            tokenRepository.Setup(x => x.GetAccessTokens(It.IsAny<DateTimeOffset>()))
                .ReturnsAsync(
                    new List<IAccessToken>()
                        {
                            new AccessToken()
                                {
                                    ClientId = "NUnit",
                                    RedirectUri = "http://localhost",
                                    Subject = "ovea"
                                }
                        });

            this.TokenRepository = tokenRepository.Object;

            this.testFixtureStopwatch = new Stopwatch();
            this.testFixtureStopwatch.Start();
        }

        [TestFixtureTearDown]
        public virtual void TestFixtureTearDown()
        {
            this.testFixtureStopwatch.Stop();

            Console.WriteLine();
            Console.WriteLine($"Time taken for all tests: {this.testFixtureStopwatch.Elapsed.ToString("g")}");
            Console.WriteLine($"##teamcity[buildStatisticValue key='{this.GetType().Name}' value='{this.testFixtureStopwatch.ElapsedMilliseconds}']");
        }

        [SetUp]
        public virtual void SetUp()
        {
            this.testStopwatch = new Stopwatch();
            this.testStopwatch.Start();
        }

        [TearDown]
        public virtual void TearDown()
        {
            this.testStopwatch.Stop();

            Console.WriteLine();
            Console.WriteLine($"Time taken for test: {this.testStopwatch.Elapsed.ToString("g")}");
            Console.WriteLine($"##teamcity[buildStatisticValue key='{this.GetType().Name}.{TestContext.CurrentContext.Test.Name}' value='{this.testStopwatch.ElapsedMilliseconds}']");
        }

        [Test]
        public async void CreateAuthorizationCode_WhenGivenValidParameters_ReturnsValidResult()
        {
            var createResult =
               await
               this.TokenProvider.CreateAuthorizationCode(
                   "NUnit",
                   "http://localhost",
                   new SentinelPrincipal(new SentinelIdentity(AuthenticationType.OAuth, new SentinelClaim(ClaimTypes.Name, "azzlack"), new SentinelClaim(ClaimType.Client, "NUnit"))),
                   null,
                   DateTimeOffset.UtcNow.AddMinutes(5));

            Console.WriteLine($"Code: {createResult.Token}");
            Console.WriteLine($"Ticket: {createResult.Entity.Ticket}");

            Assert.AreEqual("NUnit", createResult.Entity.ClientId);
            Assert.AreEqual("http://localhost", createResult.Entity.RedirectUri);
            Assert.AreEqual("azzlack", createResult.Entity.Subject);
            Assert.IsNotNullOrEmpty(createResult.Token);
        }

        [Test]
        public async void ValidateAuthorizationCode_WhenGivenValidIdentity_ReturnsValidResult()
        {
            var createResult =
               await
               this.TokenProvider.CreateAuthorizationCode(
                   "NUnit",
                   "http://localhost",
                   new SentinelPrincipal(new SentinelIdentity(AuthenticationType.OAuth, new SentinelClaim(ClaimTypes.Name, "azzlack"), new SentinelClaim(ClaimType.Client, "NUnit"))),
                   null,
                   DateTimeOffset.UtcNow.AddMinutes(5));

            var validateResult = await this.TokenProvider.ValidateAuthorizationCode(new List<IAuthorizationCode>() { createResult.Entity }, createResult.Token);

            Assert.IsTrue(validateResult.IsValid);
        }

        [Test]
        public async void ValidateAuthorizationCode_WhenGivenInvalidIdentity_ReturnsValidResult()
        {
            var createResult =
               await
               this.TokenProvider.CreateAuthorizationCode(
                   "NUnit",
                   "http://localhost",
                   new SentinelPrincipal(new SentinelIdentity(AuthenticationType.OAuth, new SentinelClaim(ClaimTypes.Name, "azzlack"), new SentinelClaim(ClaimType.Client, "NUnit"))),
                   null,
                   DateTimeOffset.UtcNow.AddMinutes(5));

            var validateResult = await this.TokenProvider.ValidateAuthorizationCode(new List<IAuthorizationCode>() { createResult.Entity }, Convert.ToBase64String(Encoding.UTF8.GetBytes("aabbccddee")));

            Assert.IsFalse(validateResult.IsValid);
        }

        [Test]
        public async void CreateAccessToken_WhenGivenValidParameters_ReturnsValidResult()
        {
            var createResult =
               await
               this.TokenProvider.CreateAccessToken(
                   "NUnit",
                   "http://localhost",
                   new SentinelPrincipal(new SentinelIdentity(AuthenticationType.OAuth, new SentinelClaim(ClaimTypes.Name, "azzlack"), new SentinelClaim(ClaimType.Client, "NUnit"))),
                   null,
                   DateTimeOffset.UtcNow.AddMinutes(5));

            Console.WriteLine($"Token: {createResult.Token}");
            Console.WriteLine($"Ticket: {createResult.Entity.Ticket}");

            Assert.AreEqual("NUnit", createResult.Entity.ClientId);
            Assert.AreEqual("http://localhost", createResult.Entity.RedirectUri);
            Assert.AreEqual("azzlack", createResult.Entity.Subject);
            Assert.IsNotNullOrEmpty(createResult.Token);
        }

        [Test]
        public async void ValidateAccessToken_WhenGivenValidIdentity_ReturnsValidResult()
        {
            var createResult =
               await
               this.TokenProvider.CreateAccessToken(
                   "NUnit",
                   "http://localhost",
                   new SentinelPrincipal(new SentinelIdentity(AuthenticationType.OAuth, new SentinelClaim(ClaimTypes.Name, "azzlack"), new SentinelClaim(ClaimType.Client, "NUnit"))),
                   null,
                   DateTimeOffset.UtcNow.AddMinutes(5));

            var validateResult = await this.TokenProvider.ValidateAccessToken(new List<IAccessToken>() { createResult.Entity }, createResult.Token);

            Assert.IsTrue(validateResult.IsValid);
        }

        [Test]
        public async void ValidateAccessToken_WhenGivenInvalidIdentity_ReturnsNotValidResult()
        {
            var createResult =
               await
               this.TokenProvider.CreateAccessToken(
                   "NUnit",
                   "http://localhost",
                   new SentinelPrincipal(new SentinelIdentity(AuthenticationType.OAuth, new SentinelClaim(ClaimTypes.Name, "azzlack"), new SentinelClaim(ClaimType.Client, "NUnit"))),
                   null,
                   DateTimeOffset.UtcNow.AddMinutes(5));

            var validateResult = await this.TokenProvider.ValidateAccessToken(new List<IAccessToken>() { createResult.Entity }, Convert.ToBase64String(Encoding.UTF8.GetBytes("aabbccddee")));

            Assert.IsFalse(validateResult.IsValid);
        }

        [Test]
        public async void CreateRefreshToken_WhenGivenValidParameters_ReturnsValidResult()
        {
            var createResult =
               await
               this.TokenProvider.CreateRefreshToken(
                   "NUnit",
                   "http://localhost",
                   new SentinelPrincipal(new SentinelIdentity(AuthenticationType.OAuth, new SentinelClaim(ClaimTypes.Name, "azzlack"), new SentinelClaim(ClaimType.Client, "NUnit"))),
                   null,
                   DateTimeOffset.UtcNow.AddMinutes(5));

            Console.WriteLine($"Token: {createResult.Token}");

            Assert.AreEqual("NUnit", createResult.Entity.ClientId);
            Assert.AreEqual("http://localhost", createResult.Entity.RedirectUri);
            Assert.AreEqual("azzlack", createResult.Entity.Subject);
            Assert.IsNotNullOrEmpty(createResult.Token);
        }

        [Test]
        public async void ValidateRefreshToken_WhenGivenValidIdentity_ReturnsValidResult()
        {
            var createResult =
               await
               this.TokenProvider.CreateRefreshToken(
                   "NUnit",
                   "http://localhost",
                   new SentinelPrincipal(new SentinelIdentity(AuthenticationType.OAuth, new SentinelClaim(ClaimTypes.Name, "azzlack"), new SentinelClaim(ClaimType.Client, "NUnit"))),
                   null,
                   DateTimeOffset.UtcNow.AddMinutes(5));

            var validateResult = await this.TokenProvider.ValidateRefreshToken(new List<IRefreshToken>() { createResult.Entity }, createResult.Token);

            Assert.IsTrue(validateResult.IsValid);
        }

        [Test]
        public async void ValidateRefreshToken_WhenGivenInvalidIdentity_ReturnsNotValidResult()
        {
            var createResult =
               await
               this.TokenProvider.CreateRefreshToken(
                   "NUnit",
                   "http://localhost",
                   new SentinelPrincipal(new SentinelIdentity(AuthenticationType.OAuth, new SentinelClaim(ClaimTypes.Name, "azzlack"), new SentinelClaim(ClaimType.Client, "NUnit"))),
                   null,
                   DateTimeOffset.UtcNow.AddMinutes(5));

            var validateResult = await this.TokenProvider.ValidateRefreshToken(new List<IRefreshToken>() { createResult.Entity }, Convert.ToBase64String(Encoding.UTF8.GetBytes("aabbccddee")));

            Assert.IsFalse(validateResult.IsValid);
        }
    }
}