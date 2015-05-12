namespace Sentinel.Tests.Unit
{
    using System;
    using System.Linq;

    using NUnit.Framework;

    using Sentinel.OAuth.Core.Interfaces.Repositories;
    using Sentinel.OAuth.Implementation;
    using Sentinel.OAuth.Models.OAuth;

    [TestFixture]
    [Category("Unit")]
    public class MemoryTokenRepositoryTests
    {
        private ITokenRepository tokenRepository;

        [SetUp]
        public void SetUp()
        {
            this.tokenRepository = new MemoryTokenRepository();
        }

        [Test]
        public async void InsertAndGet_WhenGivenValidAuthorizationCodes_ReturnsAuthorizationCodes()
        {
            await this.tokenRepository.InsertAuthorizationCode(new AuthorizationCode { Code = "123456789", ValidTo = DateTime.UtcNow.AddMinutes(1), ClientId = "NUnit", RedirectUri = "http://localhost", Subject = "Username"});
            await this.tokenRepository.InsertAuthorizationCode(new AuthorizationCode { Code = "123456789", ValidTo = DateTime.UtcNow.AddMinutes(1), ClientId = "NUnit2", RedirectUri = "http://localhost", Subject = "Username" });

            var authorizationCodes = await this.tokenRepository.GetAuthorizationCodes("http://localhost", DateTime.UtcNow);

            Assert.AreEqual(2, authorizationCodes.Count());
        }

        [Test]
        public async void InsertAndDelete_WhenGivenValidAuthorizationCodes_ReturnsTrue()
        {
            var code1 = await this.tokenRepository.InsertAuthorizationCode(new AuthorizationCode { Code = "123456789", ValidTo = DateTime.UtcNow.AddMinutes(1), ClientId = "NUnit", RedirectUri = "http://localhost", Subject = "Username" });
            var code2 = await this.tokenRepository.InsertAuthorizationCode(new AuthorizationCode { Code = "123456789", ValidTo = DateTime.UtcNow.AddMinutes(1), ClientId = "NUnit2", RedirectUri = "http://localhost", Subject = "Username" });

            var deleteResult = await this.tokenRepository.DeleteAuthorizationCode(code1);
            var authorizationCodes = await this.tokenRepository.GetAuthorizationCodes("http://localhost", DateTime.UtcNow);

            Assert.IsTrue(deleteResult);
            Assert.AreEqual(1, authorizationCodes.Count());
        }

        [Test]
        public async void InsertAndGet_WhenGivenValidAccessTokens_ReturnsAccessTokens()
        {
            await this.tokenRepository.InsertAccessToken(new AccessToken { Token = "123456789", ValidTo = DateTime.UtcNow.AddMinutes(1), ClientId = "NUnit", RedirectUri = "http://localhost" });
            await this.tokenRepository.InsertAccessToken(new AccessToken { Token = "123456789", ValidTo = DateTime.UtcNow.AddMinutes(1), ClientId = "NUnit2", RedirectUri = "http://localhost" });

            var accessTokens = await this.tokenRepository.GetAccessTokens(DateTime.UtcNow);

            Assert.AreEqual(2, accessTokens.Count());
        }

        [Test]
        public async void InsertAndDelete_WhenGivenValidAccessTokens_ReturnsTrue()
        {
            var token1 = await this.tokenRepository.InsertAccessToken(new AccessToken { Token = "123456789", ValidTo = DateTime.UtcNow.AddMinutes(1), ClientId = "NUnit", RedirectUri = "http://localhost" });
            var token2 = await this.tokenRepository.InsertAccessToken(new AccessToken { Token = "123456789", ValidTo = DateTime.UtcNow.AddMinutes(1), ClientId = "NUnit2", RedirectUri = "http://localhost" });

            var deleteResult = await this.tokenRepository.DeleteAccessToken(token1.ClientId, token1.RedirectUri, token1.Subject);
            var accessTokens = await this.tokenRepository.GetAccessTokens(DateTime.UtcNow.AddMinutes(1));

            Assert.IsTrue(deleteResult);
            Assert.AreEqual(0, accessTokens.Count());
        }

        [Test]
        public async void InsertAndGet_WhenGivenValidRefreshTokens_ReturnsRefreshTokens()
        {
            await this.tokenRepository.InsertRefreshToken(new RefreshToken { Token = "123456789", ValidTo = DateTime.UtcNow.AddMinutes(1), ClientId = "NUnit", RedirectUri = "http://localhost" });
            await this.tokenRepository.InsertRefreshToken(new RefreshToken { Token = "123456789", ValidTo = DateTime.UtcNow.AddMinutes(1), ClientId = "NUnit2", RedirectUri = "http://localhost" });

            var refreshTokens = await this.tokenRepository.GetRefreshTokens("http://localhost", DateTime.UtcNow);

            Assert.AreEqual(2, refreshTokens.Count());
        }

        [Test]
        public async void InsertAndDelete_WhenGivenValidRefreshTokens_ReturnsTrue()
        {
            var token1 = await this.tokenRepository.InsertRefreshToken(new RefreshToken { Token = "123456789", ValidTo = DateTime.UtcNow.AddMinutes(1), ClientId = "NUnit", RedirectUri = "http://localhost" });
            var token2 = await this.tokenRepository.InsertRefreshToken(new RefreshToken { Token = "123456789", ValidTo = DateTime.UtcNow.AddMinutes(1), ClientId = "NUnit2", RedirectUri = "http://localhost" });

            var deleteResult = await this.tokenRepository.DeleteRefreshToken(token1);
            var refreshTokens = await this.tokenRepository.GetRefreshTokens("http://localhost", DateTime.UtcNow);

            Assert.IsTrue(deleteResult);
            Assert.AreEqual(1, refreshTokens.Count());
        }
    }
}