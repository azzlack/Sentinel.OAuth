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

            Console.WriteLine();
            Console.WriteLine($"Time taken for test: {this.testStopwatch.Elapsed.ToString("g")}");
            Console.WriteLine($"##teamcity[buildStatisticValue key='{this.GetType().Name}.{TestContext.CurrentContext.Test.Name}' value='{this.testStopwatch.ElapsedMilliseconds}']");

            var purgeResult = this.TokenRepository.Purge().Result;
            Assert.IsTrue(purgeResult, "Purge did not work properly");
        }

        [Test]
        public async void GetAuthorizationCodes_WhenValidCodesExist_ReturnsAuthorizationCodes()
        {
            var code1 = await this.TokenRepository.InsertAuthorizationCode(new AuthorizationCode { Code = "123456789", Ticket = "abcdef", ValidTo = DateTime.UtcNow.AddMinutes(1), ClientId = "NUnit", RedirectUri = "http://localhost", Subject = "Username" });
            var code2 = await this.TokenRepository.InsertAuthorizationCode(new AuthorizationCode { Code = "123456789", Ticket = "abcdef", ValidTo = DateTime.UtcNow.AddMinutes(1), ClientId = "NUnit2", RedirectUri = "http://localhost", Subject = "Username" });

            var authorizationCodes = await this.TokenRepository.GetAuthorizationCodes("http://localhost", DateTime.UtcNow);

            Assert.AreEqual(2, authorizationCodes.Count());
        }

        [Test]
        public async void InsertAuthorizationCode_WhenGivenValidCode_ReturnsAuthorizationCodes()
        {
            var code = new AuthorizationCode
            {
                Code = "123456789",
                Ticket = "abcdef",
                ValidTo = DateTime.UtcNow.AddMinutes(1),
                ClientId = "NUnit",
                RedirectUri = "http://localhost",
                Subject = "Username"
            };

            var insertResult = await this.TokenRepository.InsertAuthorizationCode(code);

            Assert.IsNotNull(insertResult);

            Assert.AreEqual(code.ClientId, insertResult.ClientId);
            Assert.AreEqual(code.Code, insertResult.Code);
            Assert.AreEqual(code.RedirectUri, insertResult.RedirectUri);
            Assert.AreEqual(code.Subject, insertResult.Subject);
            Assert.AreEqual(code.Ticket, insertResult.Ticket);
            Assert.AreEqual(code.ValidTo, insertResult.ValidTo);
        }

        [Test]
        public async void InsertAuthorizationCode_WhenGivenInvalidCode_ThrowsException()
        {
            Assert.That(async () => await this.TokenRepository.InsertAuthorizationCode(new AuthorizationCode { Code = "123456789", ValidTo = DateTime.UtcNow.AddMinutes(1), ClientId = "NUnit", RedirectUri = "http://localhost" }), Throws.Exception.TypeOf<ArgumentException>());
            Assert.That(async () => await this.TokenRepository.InsertAuthorizationCode(new AuthorizationCode { Code = "123456789", ValidTo = DateTime.UtcNow.AddMinutes(1), ClientId = "NUnit", Subject = "Username" }), Throws.Exception.TypeOf<ArgumentException>());
            Assert.That(async () => await this.TokenRepository.InsertAuthorizationCode(new AuthorizationCode { Code = "123456789", ValidTo = DateTime.UtcNow.AddMinutes(1), RedirectUri = "http://localhost", Subject = "Username" }), Throws.Exception.TypeOf<ArgumentException>());
            Assert.That(async () => await this.TokenRepository.InsertAuthorizationCode(new AuthorizationCode { Code = "123456789", ClientId = "NUnit", RedirectUri = "http://localhost", Subject = "Username" }), Throws.Exception.TypeOf<ArgumentException>());
            Assert.That(async () => await this.TokenRepository.InsertAuthorizationCode(new AuthorizationCode { ValidTo = DateTime.UtcNow.AddMinutes(1), ClientId = "NUnit", RedirectUri = "http://localhost", Subject = "Username" }), Throws.Exception.TypeOf<ArgumentException>());
        }

        [Test]
        public async void DeleteAuthorizationCode_WhenGivenValidCode_ReturnsTrue()
        {
            var code1 = await this.TokenRepository.InsertAuthorizationCode(new AuthorizationCode { Code = "123456789", Ticket = "abcdef", ValidTo = DateTime.UtcNow.AddMinutes(1), ClientId = "NUnit", RedirectUri = "http://localhost", Subject = "Username" });

            var deleteResult = await this.TokenRepository.DeleteAuthorizationCode(code1);
            var authorizationCodes = await this.TokenRepository.GetAuthorizationCodes("http://localhost", DateTime.UtcNow.AddMinutes(1));

            Assert.IsTrue(deleteResult);
            Assert.AreEqual(0, authorizationCodes.Count(), "The authorization code was 'deleted' but is still retrievable");
        }

        [Test]
        public async void InsertAccessToken_WhenGivenInvalidToken_ThrowsException()
        {
            Assert.That(async () => await this.TokenRepository.InsertAccessToken(new AccessToken { Token = "123456789", ValidTo = DateTime.UtcNow.AddMinutes(1), ClientId = "NUnit", RedirectUri = "http://localhost" }), Throws.Exception.TypeOf<ArgumentException>());
            Assert.That(async () => await this.TokenRepository.InsertAccessToken(new AccessToken { Token = "123456789", ValidTo = DateTime.UtcNow.AddMinutes(1), ClientId = "NUnit" }), Throws.Exception.TypeOf<ArgumentException>());
            Assert.That(async () => await this.TokenRepository.InsertAccessToken(new AccessToken { Token = "123456789", ValidTo = DateTime.UtcNow.AddMinutes(1), RedirectUri = "http://localhost" }), Throws.Exception.TypeOf<ArgumentException>());
            Assert.That(async () => await this.TokenRepository.InsertAccessToken(new AccessToken { Token = "123456789", ClientId = "NUnit", RedirectUri = "http://localhost" }), Throws.Exception.TypeOf<ArgumentException>());
            Assert.That(async () => await this.TokenRepository.InsertAccessToken(new AccessToken { ValidTo = DateTime.UtcNow.AddMinutes(1), ClientId = "NUnit", RedirectUri = "http://localhost" }), Throws.Exception.TypeOf<ArgumentException>());
        }

        [Test]
        public async void InsertAccessToken_WhenGivenValidAccessToken_ReturnsAccessToken()
        {
            var token = new AccessToken
            {
                Token = "123456789",
                Ticket = "abcdef",
                ValidTo = DateTime.UtcNow,
                ClientId = "NUnit",
                RedirectUri = "http://localhost",
                Subject = "ovea"
            };
            var result = await this.TokenRepository.InsertAccessToken(token);

            Assert.AreEqual(token.ClientId, result.ClientId);
            Assert.AreEqual(token.RedirectUri, result.RedirectUri);
            Assert.AreEqual(token.Subject, result.Subject);
            Assert.AreEqual(token.Ticket, result.Ticket);
            Assert.AreEqual(token.Token, result.Token);
            Assert.AreEqual(token.ValidTo, result.ValidTo);
        }

        [Test]
        public async void GetAccessTokens_WhenValidTokensExists_ReturnsAccessTokens()
        {
            await this.TokenRepository.InsertAccessToken(new AccessToken { Token = "123456789", Ticket = "abcdef", ValidTo = DateTime.UtcNow, ClientId = "NUnit", RedirectUri = "http://localhost", Subject = "ovea" });
            await this.TokenRepository.InsertAccessToken(new AccessToken { Token = "123456789", Ticket = "abcdef", ValidTo = DateTime.UtcNow.AddMinutes(1), ClientId = "NUnit2", RedirectUri = "http://localhost", Subject = "ovea" });

            var accessTokens = await this.TokenRepository.GetAccessTokens(DateTime.UtcNow);

            Assert.AreNotEqual(2, accessTokens.Count(), "Got back token that was supposed to be expired");
            Assert.AreEqual(1, accessTokens.Count());
        }

        [Test]
        public async void GetAccessTokens_WhenValidTokensExistsForSubject_ReturnsAccessTokens()
        {
            await this.TokenRepository.InsertAccessToken(new AccessToken { Token = "123456789", Ticket = "abcdef", ValidTo = DateTime.UtcNow.AddMinutes(1), ClientId = "NUnit", RedirectUri = "http://localhost", Subject = "ovea" });
            await this.TokenRepository.InsertAccessToken(new AccessToken { Token = "123456789", Ticket = "abcdef", ValidTo = DateTime.UtcNow.AddMinutes(1), ClientId = "NUnit2", RedirectUri = "http://localhost", Subject = "ovea2" });

            var accessTokens = await this.TokenRepository.GetAccessTokens("ovea", DateTime.UtcNow);

            Assert.AreEqual(1, accessTokens.Count());
        }

        [Test]
        public async void DeleteAccessToken_WhenGivenValidToken_ReturnsTrue()
        {
            var token1 = await this.TokenRepository.InsertAccessToken(new AccessToken { Token = "123456789", Ticket = "abcdef", ValidTo = DateTime.UtcNow.AddMinutes(1), ClientId = "NUnit", RedirectUri = "http://localhost", Subject = "ovea" });

            var deleteResult = await this.TokenRepository.DeleteAccessToken(token1);
            var accessTokens = await this.TokenRepository.GetAccessTokens(DateTime.UtcNow.AddMinutes(1));

            Assert.IsTrue(deleteResult);
            Assert.AreEqual(0, accessTokens.Count(), "The access token was 'deleted' but is still retrievable");
        }

        [Test]
        public async void DeleteAccessTokens_WhenGivenExpirationDate_ReturnsNumberOfDeletedTokens()
        {
            await this.TokenRepository.InsertAccessToken(new AccessToken { Token = "123456789", Ticket = "abcdef", ValidTo = DateTime.UtcNow, ClientId = "NUnit", RedirectUri = "http://localhost", Subject = "ovea" });

            var deleteResult = await this.TokenRepository.DeleteAccessTokens(DateTime.UtcNow);
            var accessTokens = await this.TokenRepository.GetAccessTokens(DateTime.UtcNow);

            Assert.AreEqual(1, deleteResult);
            Assert.AreEqual(0, accessTokens.Count(), "The access token was 'deleted' but is still retrievable");
        }

        [Test]
        public async void DeleteAccessTokens_WhenGivenValidParams_ReturnsNumberOfDeletedAccessTokens()
        {
            var token1 = await this.TokenRepository.InsertAccessToken(new AccessToken { Token = "123456789", Ticket = "abcdef", ValidTo = DateTime.UtcNow, ClientId = "NUnit", RedirectUri = "http://localhost", Subject = "ovea" });

            var deleteResult = await this.TokenRepository.DeleteAccessTokens(token1.ClientId, token1.RedirectUri, token1.Subject);
            var accessTokens = await this.TokenRepository.GetAccessTokens(DateTime.UtcNow);

            Assert.AreEqual(1, deleteResult);
            Assert.AreEqual(0, accessTokens.Count(), "The access token was 'deleted' but is still retrievable");
        }

        [Test]
        public async void InsertRefreshToken_WhenGivenInvalidToken_ThrowsException()
        {
            Assert.That(async () => await this.TokenRepository.InsertRefreshToken(new RefreshToken { Token = "123456789", ValidTo = DateTime.UtcNow.AddMinutes(1), ClientId = "NUnit", RedirectUri = "http://localhost" }), Throws.Exception.TypeOf<ArgumentException>());
            Assert.That(async () => await this.TokenRepository.InsertRefreshToken(new RefreshToken { Token = "123456789", ValidTo = DateTime.UtcNow.AddMinutes(1), ClientId = "NUnit" }), Throws.Exception.TypeOf<ArgumentException>());
            Assert.That(async () => await this.TokenRepository.InsertRefreshToken(new RefreshToken { Token = "123456789", ValidTo = DateTime.UtcNow.AddMinutes(1), RedirectUri = "http://localhost" }), Throws.Exception.TypeOf<ArgumentException>());
            Assert.That(async () => await this.TokenRepository.InsertRefreshToken(new RefreshToken { Token = "123456789", ClientId = "NUnit", RedirectUri = "http://localhost" }), Throws.Exception.TypeOf<ArgumentException>());
            Assert.That(async () => await this.TokenRepository.InsertRefreshToken(new RefreshToken { ValidTo = DateTime.UtcNow.AddMinutes(1), ClientId = "NUnit", RedirectUri = "http://localhost" }), Throws.Exception.TypeOf<ArgumentException>());
        }

        [Test]
        public async void InsertRefreshToken_WhenGivenValidTokens_ReturnsRefreshToken()
        {
            var token = new RefreshToken
            {
                Token = "123456789",
                ValidTo = DateTime.UtcNow.AddMinutes(1),
                ClientId = "NUnit",
                RedirectUri = "http://localhost",
                Subject = "ovea"
            };
            var result = await this.TokenRepository.InsertRefreshToken(token);

            Assert.AreEqual(token.ClientId, result.ClientId);
            Assert.AreEqual(token.RedirectUri, result.RedirectUri);
            Assert.AreEqual(token.Subject, result.Subject);
            Assert.AreEqual(token.Token, result.Token);
            Assert.AreEqual(token.ValidTo, result.ValidTo);
        }

        [Test]
        public async void GetRefreshTokens_WhenValidTokensExist_ReturnsRefreshTokens()
        {
            await this.TokenRepository.InsertRefreshToken(new RefreshToken { Token = "123456789", ValidTo = DateTime.UtcNow, ClientId = "NUnit", RedirectUri = "http://localhost", Subject = "ovea" });
            await this.TokenRepository.InsertRefreshToken(new RefreshToken { Token = "123456789", ValidTo = DateTime.UtcNow.AddMinutes(1), ClientId = "NUnit", RedirectUri = "http://localhost", Subject = "ovea" });

            var refreshTokens = await this.TokenRepository.GetRefreshTokens("NUnit", "http://localhost", DateTime.UtcNow);

            Assert.AreNotEqual(2, refreshTokens.Count(), "Got back expired token");
            Assert.AreEqual(1, refreshTokens.Count());
        }

        [Test]
        public async void DeleteRefreshToken_WhenGivenValidToken_ReturnsTrue()
        {
            var token1 = await this.TokenRepository.InsertRefreshToken(new RefreshToken { Token = "123456789", ValidTo = DateTime.UtcNow.AddMinutes(1), ClientId = "NUnit", RedirectUri = "http://localhost", Subject = "ovea" });

            var deleteResult = await this.TokenRepository.DeleteRefreshToken(token1);
            var refreshTokens = await this.TokenRepository.GetRefreshTokens("NUnit2", "http://localhost", DateTime.UtcNow.AddMinutes(1));

            Assert.IsTrue(deleteResult);
            Assert.AreEqual(0, refreshTokens.Count(), "The refresh token was 'deleted' but is still retrievable");
        }

        [Test]
        public async void DeleteAccessTokens_WhenGivenExpirationDate_ReturnsNumberOfDeletedRefreshTokens()
        {
            var insertResult = await this.TokenRepository.InsertRefreshToken(new RefreshToken() { Token = "123456789", ValidTo = DateTime.UtcNow, ClientId = "NUnit", RedirectUri = "http://localhost", Subject = "ovea" });

            var deleteResult = await this.TokenRepository.DeleteRefreshTokens(DateTime.UtcNow);
            var accessTokens = await this.TokenRepository.GetRefreshTokens(insertResult.ClientId, insertResult.RedirectUri, DateTime.UtcNow);

            Assert.AreEqual(1, deleteResult);
            Assert.AreEqual(0, accessTokens.Count(), "The refresh token was 'deleted' but is still retrievable");
        }
    }
}