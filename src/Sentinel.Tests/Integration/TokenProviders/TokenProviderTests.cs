namespace Sentinel.Tests.Integration.TokenProviders
{
    using NUnit.Framework;
    using Sentinel.OAuth.Core.Constants.Identity;
    using Sentinel.OAuth.Core.Interfaces.Providers;
    using Sentinel.OAuth.Models.Identity;
    using System;
    using System.Diagnostics;
    using System.Security.Claims;

    public abstract class TokenProviderTests
    {
        private Stopwatch testFixtureStopwatch;

        private Stopwatch testStopwatch;

        public ITokenProvider TokenProvider { get; set; }

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
        public async void CreateAuthorizationCode_WhenGivenValidParameters_ReturnsValidCode()
        {
            var result =
               await
               this.TokenProvider.CreateAuthorizationCode(
                   "NUnit",
                   "http://localhost",
                   new SentinelPrincipal(new SentinelIdentity(AuthenticationType.OAuth, new SentinelClaim(ClaimTypes.Name, "azzlack"), new SentinelClaim(ClaimType.Client, "NUnit"))),
                   null,
                   DateTimeOffset.UtcNow.AddMinutes(5));

            Console.WriteLine($"Code: {result.Token}");
            Console.WriteLine($"Ticket: {result.Entity.Ticket}");

            Assert.AreEqual("NUnit", result.Entity.ClientId);
            Assert.AreEqual("http://localhost", result.Entity.RedirectUri);
            Assert.AreEqual("azzlack", result.Entity.Subject);
            Assert.IsNotNullOrEmpty(result.Token);
        }

        [Test]
        public async void AuthenticateAuthorizationCode_WhenGivenValidIdentity_ReturnsAuthenticatedIdentity()
        {
            var createResult =
               await
               this.TokenProvider.CreateAuthorizationCode(
                   "NUnit",
                   "http://localhost",
                   new SentinelPrincipal(new SentinelIdentity(AuthenticationType.OAuth, new SentinelClaim(ClaimTypes.Name, "azzlack"), new SentinelClaim(ClaimType.Client, "NUnit"))),
                   null,
                   DateTimeOffset.UtcNow.AddMinutes(5));

            var validateResult = await this.TokenProvider.ValidateAuthorizationCode(createResult.Token);

            Assert.IsTrue(validateResult);
        }
    }
}