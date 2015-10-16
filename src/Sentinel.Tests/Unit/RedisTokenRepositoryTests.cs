namespace Sentinel.Tests.Unit
{
    using Common.Logging;
    using NUnit.Framework;
    using Sentinel.OAuth.TokenManagers.RedisTokenRepository.Implementation;
    using Sentinel.OAuth.TokenManagers.RedisTokenRepository.Models;
    using System.Configuration;

    [TestFixture]
    [Category("Unit")]
    public class RedisTokenRepositoryTests : TokenRepositoryTests
    {
        [SetUp]
        public override void SetUp()
        {
            this.TokenRepository =
                new RedisTokenRepository(
                    new RedisTokenRepositoryConfiguration(
                        ConfigurationManager.AppSettings["RedisHost"],
                        4,
                        "sentinel.oauth.RedisTokenRepositoryTests",
                        LogManager.GetLogger(typeof(RedisTokenRepositoryTests))));

            base.SetUp();
        }
    }
}