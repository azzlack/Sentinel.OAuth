namespace Sentinel.Tests.Unit
{
    using NUnit.Framework;
    using Sentinel.OAuth.Core.Interfaces.Repositories;
    using Sentinel.OAuth.Core.Models.OAuth;
    using System;
    using System.Diagnostics;
    using System.Linq;

    public abstract class TokenRepositoryTests
    {
        private Stopwatch testFixtureStopwatch;

        private Stopwatch testStopwatch;

        public ITokenRepository TokenRepository { get; set; }

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
            Console.WriteLine($"##teamcity[buildStatisticValue key='{this.GetType().Name}' value='{this.testStopwatch.ElapsedMilliseconds}']");
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

            this.TokenRepository.Purge();

            Console.WriteLine();
            Console.WriteLine($"Time taken for test: {this.testStopwatch.Elapsed.ToString("g")}");
            Console.WriteLine($"##teamcity[buildStatisticValue key='{this.GetType().Name}.{TestContext.CurrentContext.Test.Name}' value='{this.testStopwatch.ElapsedMilliseconds}']");
        }

        [Test]
        public async void InsertAndGet_WhenGivenValidAuthorizationCodes_ReturnsAuthorizationCodes()
        {
            var code1 = await this.TokenRepository.InsertAuthorizationCode(new AuthorizationCode { Code = "123456789", Ticket = "abcdef", ValidTo = DateTime.UtcNow.AddMinutes(1), ClientId = "NUnit", RedirectUri = "http://localhost", Subject = "Username" });
            var code2 = await this.TokenRepository.InsertAuthorizationCode(new AuthorizationCode { Code = "123456789", Ticket = "abcdef", ValidTo = DateTime.UtcNow.AddMinutes(1), ClientId = "NUnit2", RedirectUri = "http://localhost", Subject = "Username" });

            var authorizationCodes = await this.TokenRepository.GetAuthorizationCodes("http://localhost", DateTime.UtcNow);

            Assert.AreEqual(2, authorizationCodes.Count());
        }

        [Test]
        public async void Insert_WhenGivenInvalidAuthorizationCode_ThrowsException()
        {
            Assert.That(async () => await this.TokenRepository.InsertAuthorizationCode(new AuthorizationCode { Code = "123456789", ValidTo = DateTime.UtcNow.AddMinutes(1), ClientId = "NUnit", RedirectUri = "http://localhost" }), Throws.Exception.TypeOf<ArgumentException>());
            Assert.That(async () => await this.TokenRepository.InsertAuthorizationCode(new AuthorizationCode { Code = "123456789", ValidTo = DateTime.UtcNow.AddMinutes(1), ClientId = "NUnit", Subject = "Username" }), Throws.Exception.TypeOf<ArgumentException>());
            Assert.That(async () => await this.TokenRepository.InsertAuthorizationCode(new AuthorizationCode { Code = "123456789", ValidTo = DateTime.UtcNow.AddMinutes(1), RedirectUri = "http://localhost", Subject = "Username" }), Throws.Exception.TypeOf<ArgumentException>());
            Assert.That(async () => await this.TokenRepository.InsertAuthorizationCode(new AuthorizationCode { Code = "123456789", ClientId = "NUnit", RedirectUri = "http://localhost", Subject = "Username" }), Throws.Exception.TypeOf<ArgumentException>());
            Assert.That(async () => await this.TokenRepository.InsertAuthorizationCode(new AuthorizationCode { ValidTo = DateTime.UtcNow.AddMinutes(1), ClientId = "NUnit", RedirectUri = "http://localhost", Subject = "Username" }), Throws.Exception.TypeOf<ArgumentException>());
        }

        [Test]
        public async void InsertAndDelete_WhenGivenValidAuthorizationCodes_ReturnsTrue()
        {
            var code1 = await this.TokenRepository.InsertAuthorizationCode(new AuthorizationCode { Code = "123456789", Ticket = "abcdef", ValidTo = DateTime.UtcNow.AddMinutes(1), ClientId = "NUnit", RedirectUri = "http://localhost", Subject = "Username" });

            var deleteResult = await this.TokenRepository.DeleteAuthorizationCode(code1);
            var authorizationCodes = await this.TokenRepository.GetAuthorizationCodes("http://localhost", DateTime.UtcNow.AddMinutes(1));

            Assert.IsTrue(deleteResult);
            Assert.AreEqual(0, authorizationCodes.Count(), "The authorization code was 'deleted' but is still retrievable");
        }

        [Test]
        public async void Insert_WhenGivenInvalidAccessToken_ThrowsException()
        {
            Assert.That(async () => await this.TokenRepository.InsertAccessToken(new AccessToken { Token = "123456789", ValidTo = DateTime.UtcNow.AddMinutes(1), ClientId = "NUnit", RedirectUri = "http://localhost" }), Throws.Exception.TypeOf<ArgumentException>());
            Assert.That(async () => await this.TokenRepository.InsertAccessToken(new AccessToken { Token = "123456789", ValidTo = DateTime.UtcNow.AddMinutes(1), ClientId = "NUnit" }), Throws.Exception.TypeOf<ArgumentException>());
            Assert.That(async () => await this.TokenRepository.InsertAccessToken(new AccessToken { Token = "123456789", ValidTo = DateTime.UtcNow.AddMinutes(1), RedirectUri = "http://localhost" }), Throws.Exception.TypeOf<ArgumentException>());
            Assert.That(async () => await this.TokenRepository.InsertAccessToken(new AccessToken { Token = "123456789", ClientId = "NUnit", RedirectUri = "http://localhost" }), Throws.Exception.TypeOf<ArgumentException>());
            Assert.That(async () => await this.TokenRepository.InsertAccessToken(new AccessToken { ValidTo = DateTime.UtcNow.AddMinutes(1), ClientId = "NUnit", RedirectUri = "http://localhost" }), Throws.Exception.TypeOf<ArgumentException>());
        }

        [Test]
        public async void InsertAndGet_WhenGivenValidAccessTokens_ReturnsAccessTokens()
        {
            await this.TokenRepository.InsertAccessToken(new AccessToken { Token = "123456789", Ticket = "abcdef", ValidTo = DateTime.UtcNow.AddMinutes(1), ClientId = "NUnit", RedirectUri = "http://localhost", Subject = "ovea" });
            await this.TokenRepository.InsertAccessToken(new AccessToken { Token = "123456789", Ticket = "abcdef", ValidTo = DateTime.UtcNow.AddMinutes(1), ClientId = "NUnit2", RedirectUri = "http://localhost", Subject = "ovea" });

            var accessTokens = await this.TokenRepository.GetAccessTokens(DateTime.UtcNow);

            Assert.AreEqual(2, accessTokens.Count());
        }

        [Test]
        public async void InsertAndDelete_WhenGivenValidAccessTokens_ReturnsTrue()
        {
            var token1 = await this.TokenRepository.InsertAccessToken(new AccessToken { Token = "123456789", Ticket = "abcdef", ValidTo = DateTime.UtcNow.AddMinutes(1), ClientId = "NUnit", RedirectUri = "http://localhost", Subject = "ovea" });

            var deleteResult = await this.TokenRepository.DeleteAccessToken(token1);
            var accessTokens = await this.TokenRepository.GetAccessTokens(DateTime.UtcNow.AddMinutes(1));

            Assert.IsTrue(deleteResult);
            Assert.AreEqual(0, accessTokens.Count(), "The access token was 'deleted' but is still retrievable");
        }

        [Test]
        public async void Insert_WhenGivenInvalidRefreshToken_ThrowsException()
        {
            Assert.That(async () => await this.TokenRepository.InsertRefreshToken(new RefreshToken { Token = "123456789", ValidTo = DateTime.UtcNow.AddMinutes(1), ClientId = "NUnit", RedirectUri = "http://localhost" }), Throws.Exception.TypeOf<ArgumentException>());
            Assert.That(async () => await this.TokenRepository.InsertRefreshToken(new RefreshToken { Token = "123456789", ValidTo = DateTime.UtcNow.AddMinutes(1), ClientId = "NUnit" }), Throws.Exception.TypeOf<ArgumentException>());
            Assert.That(async () => await this.TokenRepository.InsertRefreshToken(new RefreshToken { Token = "123456789", ValidTo = DateTime.UtcNow.AddMinutes(1), RedirectUri = "http://localhost" }), Throws.Exception.TypeOf<ArgumentException>());
            Assert.That(async () => await this.TokenRepository.InsertRefreshToken(new RefreshToken { Token = "123456789", ClientId = "NUnit", RedirectUri = "http://localhost" }), Throws.Exception.TypeOf<ArgumentException>());
            Assert.That(async () => await this.TokenRepository.InsertRefreshToken(new RefreshToken { ValidTo = DateTime.UtcNow.AddMinutes(1), ClientId = "NUnit", RedirectUri = "http://localhost" }), Throws.Exception.TypeOf<ArgumentException>());
        }

        [Test]
        public async void InsertAndGet_WhenGivenValidRefreshTokens_ReturnsRefreshTokens()
        {
            await this.TokenRepository.InsertRefreshToken(new RefreshToken { Token = "123456789", ValidTo = DateTime.UtcNow.AddMinutes(1), ClientId = "NUnit", RedirectUri = "http://localhost", Subject = "ovea" });
            await this.TokenRepository.InsertRefreshToken(new RefreshToken { Token = "123456789", ValidTo = DateTime.UtcNow.AddMinutes(1), ClientId = "NUnit", RedirectUri = "http://localhost", Subject = "ovea" });

            var refreshTokens = await this.TokenRepository.GetRefreshTokens("NUnit", "http://localhost", DateTime.UtcNow);

            Assert.AreEqual(2, refreshTokens.Count());
        }

        [Test]
        public async void InsertAndDelete_WhenGivenValidRefreshTokens_ReturnsTrue()
        {
            var token1 = await this.TokenRepository.InsertRefreshToken(new RefreshToken { Token = "123456789", ValidTo = DateTime.UtcNow.AddMinutes(1), ClientId = "NUnit", RedirectUri = "http://localhost", Subject = "ovea" });

            var deleteResult = await this.TokenRepository.DeleteRefreshToken(token1);
            var refreshTokens = await this.TokenRepository.GetRefreshTokens("NUnit2", "http://localhost", DateTime.UtcNow.AddMinutes(1));

            Assert.IsTrue(deleteResult);
            Assert.AreEqual(0, refreshTokens.Count(), "The refresh token was 'deleted' but is still retrievable");
        }
    }
}