namespace Sentinel.Tests.Integration.TokenManagers
{
    using NUnit.Framework;
    using Sentinel.OAuth.Core.Constants.Identity;
    using Sentinel.OAuth.Core.Interfaces.Managers;
    using Sentinel.OAuth.Models.Identity;
    using Sentinel.Tests.Constants;
    using System;
    using System.Diagnostics;
    using System.Globalization;
    using System.Security.Claims;

    public abstract class TokenManagerTests
    {
        private Stopwatch testFixtureStopwatch;

        private Stopwatch testStopwatch;

        public ITokenManager TokenManager { get; set; }

        [TestFixtureSetUp]
        public virtual void TestFixtureSetUp()
        {
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
        public async void CreateAuthorizationCode_WhenGivenValidIdentity_ReturnsValidCode()
        {
            var code =
               await
               this.TokenManager.CreateAuthorizationCodeAsync(
                   new SentinelPrincipal(
                   new SentinelIdentity(AuthenticationType.OAuth, new SentinelClaim(ClaimTypes.Name, "azzlack"), new SentinelClaim(ClaimType.Client, "NUnit"))),
                   TimeSpan.FromMinutes(5),
                   "http://localhost",
                   null);

            Console.WriteLine("Code: {0}", code.Token);

            Assert.IsNotNullOrEmpty(code.Token);
        }

        [Test]
        public async void AuthenticateAuthorizationCode_WhenGivenValidIdentity_ReturnsAuthenticatedIdentity()
        {
            var code =
                await
                this.TokenManager.CreateAuthorizationCodeAsync(
                    new SentinelPrincipal(
                    new SentinelIdentity(AuthenticationType.OAuth, new SentinelClaim(ClaimTypes.Name, "azzlack"), new SentinelClaim(ClaimType.Client, "NUnit"))),
                    TimeSpan.FromMinutes(5),
                    "http://localhost",
                    null);

            Console.WriteLine();
            var createAccessTokenElapsed = this.testStopwatch.Elapsed;
            Console.WriteLine($"Creating authorization code took {createAccessTokenElapsed} seconds");

            Console.WriteLine("Code: {0}", code.Token);

            var user = await this.TokenManager.AuthenticateAuthorizationCodeAsync("http://localhost", code.Token);

            Console.WriteLine();
            Console.WriteLine($"Authenticating authorization code took {this.testStopwatch.Elapsed - createAccessTokenElapsed} seconds");
            Console.WriteLine($"##teamcity[buildStatisticValue key='{this.GetType().Name}.AuthenticateAuthorizationCodeAsync' value='{(this.testStopwatch.Elapsed - createAccessTokenElapsed).TotalMilliseconds.ToString(CultureInfo.InvariantCulture)}']");

            Assert.IsTrue(user.Identity.IsAuthenticated);
        }

        [Test]
        public async void AuthenticateAuthorizationCode_WhenGivenUsingCodeTwice_ReturnsNotAuthenticatedIdentity()
        {
            var code =
                await
                this.TokenManager.CreateAuthorizationCodeAsync(
                    new SentinelPrincipal(
                    new SentinelIdentity(AuthenticationType.OAuth, new SentinelClaim(ClaimTypes.Name, "azzlack"), new SentinelClaim(ClaimType.Client, "NUnit"))),
                    TimeSpan.FromMinutes(5),
                    "http://localhost",
                    new[] { Scope.Read });

            Console.WriteLine();
            var createAuthorizationCodeElapsed = this.testStopwatch.Elapsed;
            Console.WriteLine($"Creating access token took {createAuthorizationCodeElapsed} seconds");

            Console.WriteLine("Code: {0}", code.Token);

            var user1 = await this.TokenManager.AuthenticateAuthorizationCodeAsync("http://localhost", code.Token);

            Console.WriteLine();
            Console.WriteLine($"Authenticating authorization code took {this.testStopwatch.Elapsed - createAuthorizationCodeElapsed} seconds");

            var user2 = await this.TokenManager.AuthenticateAuthorizationCodeAsync("http://localhost", code.Token);

            Assert.IsFalse(user2.Identity.IsAuthenticated, "The code is possible to use twice");
        }

        [Test]
        public async void CreateAccessToken_WhenGivenValidIdentity_ReturnsAccessToken()
        {
            var token =
                await
                this.TokenManager.CreateAccessTokenAsync(
                    new SentinelPrincipal(
                    new SentinelIdentity(AuthenticationType.OAuth, new SentinelClaim(ClaimTypes.Name, "azzlack"), new SentinelClaim(ClaimType.Client, "NUnit"))),
                    TimeSpan.FromHours(1),
                    "NUnit",
                    "http://localhost",
                    new[] { Scope.Read });

            Console.WriteLine();
            var createAccessTokenElapsed = this.testStopwatch.Elapsed;
            Console.WriteLine($"Creating access token took {createAccessTokenElapsed} seconds");

            Console.WriteLine("Token: {0}", token.Token);

            Assert.IsNotNullOrEmpty(token.Token);
        }

        [Test]
        public async void AuthenticateAccessToken_WhenGivenValidIdentity_ReturnsAuthenticatedIdentity()
        {
            var token =
                await
                this.TokenManager.CreateAccessTokenAsync(
                    new SentinelPrincipal(
                    new SentinelIdentity(AuthenticationType.OAuth, new SentinelClaim(ClaimTypes.Name, "azzlack"), new SentinelClaim(ClaimType.Client, "NUnit"))),
                    TimeSpan.FromHours(1),
                    "NUnit",
                    "http://localhost",
                    new[] { Scope.Read });

            Console.WriteLine();
            var createAccessTokenElapsed = this.testStopwatch.Elapsed;
            Console.WriteLine($"Creating access token took {createAccessTokenElapsed} seconds");

            Console.WriteLine("Token: {0}", token.Token);

            var user = await this.TokenManager.AuthenticateAccessTokenAsync(token.Token);

            Console.WriteLine();
            Console.WriteLine($"Authenticating access token took {this.testStopwatch.Elapsed - createAccessTokenElapsed} seconds");
            Console.WriteLine($"##teamcity[buildStatisticValue key='{this.GetType().Name}.AuthenticateAccessTokenAsync' value='{(this.testStopwatch.Elapsed - createAccessTokenElapsed).TotalMilliseconds.ToString(CultureInfo.InvariantCulture)}']");

            Assert.IsTrue(user.Identity.IsAuthenticated);
        }

        [Test]
        public async void AuthenticateAccessToken_WhenUsingExpiredToken_ReturnsNotAuthenticatedIdentity()
        {
            var token =
                await
                this.TokenManager.CreateAccessTokenAsync(
                    new SentinelPrincipal(
                    new SentinelIdentity(AuthenticationType.OAuth, new SentinelClaim(ClaimTypes.Name, "azzlack"), new SentinelClaim(ClaimType.Client, "NUnit"))),
                    TimeSpan.FromSeconds(0),
                    "NUnit",
                    "http://localhost",
                    new[] { Scope.Read });

            Console.WriteLine();
            var createAccessTokenElapsed = this.testStopwatch.Elapsed;
            Console.WriteLine($"Creating access token took {createAccessTokenElapsed} seconds");

            Console.WriteLine("Token: {0}", token.Token);

            var user = await this.TokenManager.AuthenticateAccessTokenAsync(token.Token);

            Console.WriteLine();
            Console.WriteLine($"Authenticating access token took {this.testStopwatch.Elapsed - createAccessTokenElapsed} seconds");

            Assert.IsFalse(user.Identity.IsAuthenticated, "The token is possible to use after expiration");
        }

        [Test]
        public async void CreateRefreshToken_WhenGivenValidIdentity_ReturnsValidToken()
        {
            var token =
                await
                this.TokenManager.CreateRefreshTokenAsync(
                    new SentinelPrincipal(
                    new SentinelIdentity(AuthenticationType.OAuth, new SentinelClaim(ClaimTypes.Name, "azzlack"), new SentinelClaim(ClaimType.Client, "NUnit"))),
                    TimeSpan.FromDays(90),
                    "NUnit",
                    "http://localhost",
                    new[] { Scope.Read });

            Console.WriteLine();
            var createRefreshTokenElapsed = this.testStopwatch.Elapsed;
            Console.WriteLine($"Creating refresh token took {createRefreshTokenElapsed} seconds");

            Console.WriteLine("Token: {0}", token.Token);

            Assert.IsNotNullOrEmpty(token.Token);
        }

        [Test]
        public async void AuthenticateRefreshToken_WhenGivenValidIdentity_ReturnsAuthenticatedIdentity()
        {
            var token =
                await
                this.TokenManager.CreateRefreshTokenAsync(
                    new SentinelPrincipal(
                    new SentinelIdentity(AuthenticationType.OAuth, new SentinelClaim(ClaimTypes.Name, "azzlack"), new SentinelClaim(ClaimType.Client, "NUnit"))),
                    TimeSpan.FromDays(90),
                    "NUnit",
                    "http://localhost",
                    new[] { Scope.Read });

            Console.WriteLine();
            var createRefreshTokenElapsed = this.testStopwatch.Elapsed;
            Console.WriteLine($"Creating access token took {createRefreshTokenElapsed} seconds");

            Console.WriteLine("Token: {0}", token.Token);

            var user = await this.TokenManager.AuthenticateRefreshTokenAsync("NUnit", token.Token);

            Console.WriteLine();
            Console.WriteLine($"Authenticating refresh token took {this.testStopwatch.Elapsed - createRefreshTokenElapsed} seconds");
            Console.WriteLine($"##teamcity[buildStatisticValue key='{this.GetType().Name}.AuthenticateRefreshTokenAsync' value='{(this.testStopwatch.Elapsed - createRefreshTokenElapsed).TotalMilliseconds.ToString(CultureInfo.InvariantCulture)}']");

            Assert.IsTrue(user.Identity.IsAuthenticated);
        }

        [Test]
        public async void AuthenticateRefreshToken_WhenUsingExpiredToken_ReturnsNotAuthenticatedIdentity()
        {
            var token =
                await
                this.TokenManager.CreateRefreshTokenAsync(
                    new SentinelPrincipal(
                    new SentinelIdentity(AuthenticationType.OAuth, new SentinelClaim(ClaimTypes.Name, "azzlack"), new SentinelClaim(ClaimType.Client, "NUnit"))),
                    TimeSpan.FromSeconds(-5),
                    "NUnit",
                    "http://localhost",
                    new[] { Scope.Read });

            Console.WriteLine();
            var createRefreshTokenElapsed = this.testStopwatch.Elapsed;
            Console.WriteLine($"Creating access token took {createRefreshTokenElapsed} seconds");

            Console.WriteLine("Token: {0}", token.Token);

            var user = await this.TokenManager.AuthenticateRefreshTokenAsync("NUnit", token.Token);

            Console.WriteLine();
            Console.WriteLine($"Authenticating refresh token took {this.testStopwatch.Elapsed - createRefreshTokenElapsed} seconds");

            Assert.IsFalse(user.Identity.IsAuthenticated, "The token is possible to use after expiration");
        }
    }
}