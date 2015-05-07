namespace Sentinel.Tests.Integration.TokenManagers
{
    using System;
    using System.Data;
    using System.Data.SqlLocalDb;
    using System.Security.Claims;

    using Common.Logging;

    using Dapper;

    using Moq;

    using NUnit.Framework;

    using Sentinel.OAuth.Core.Constants.Identity;
    using Sentinel.OAuth.Core.Interfaces.Managers;
    using Sentinel.OAuth.Implementation;
    using Sentinel.OAuth.Models.Identity;
    using Sentinel.OAuth.TokenManagers.SqlServerTokenRepository.Implementation;
    using Sentinel.OAuth.TokenManagers.SqlServerTokenRepository.Models;

    public class SqlServerTokenRepositoryTests
    {
        /// <summary>The instance.</summary>
        private SqlLocalDbInstance instance;

        private string databaseName;

        private ITokenManager tokenManager;

        /// <summary>
        /// The test fixture set up.
        /// </summary>
        /// <exception cref="Exception">
        /// </exception>
        [TestFixtureSetUp]
        public void TestFixtureSetUp()
        {
            var localDb = new SqlLocalDbApiWrapper();

            if (!localDb.IsLocalDBInstalled())
            {
                throw new Exception("LocalDB is not installed!");
            }

            var provider = new SqlLocalDbProvider();

            this.databaseName = "SqlServerTokenRepositoryTests" + Guid.NewGuid().ToString("N");

            // Configure dapper to support datetime2
            SqlMapper.AddTypeMap(typeof(DateTime), DbType.DateTime2);

            // Create test instance
            this.instance = provider.CreateInstance(Guid.NewGuid().ToString("N"));
            this.instance.Start();

            // Seed test data
            using (var connection = this.instance.CreateConnection())
            {
                connection.Open();

                try
                {
                    connection.Execute("CREATE DATABASE " + this.databaseName);
                    connection.Execute("USE " + this.databaseName);
                    connection.Execute("CREATE TABLE AccessTokens (Id bigint NOT NULL PRIMARY KEY IDENTITY(1,1), ClientId VARCHAR(255) NOT NULL, Ticket VARCHAR(MAX) NOT NULL, Token VARCHAR(MAX) NOT NULL, Subject NVARCHAR(255) NOT NULL, RedirectUri VARCHAR(MAX), ValidTo DATETIME2, Created DATETIME2)");
                    connection.Execute("CREATE TABLE RefreshTokens (Id bigint NOT NULL PRIMARY KEY IDENTITY(1,1), ClientId VARCHAR(255) NOT NULL, Token VARCHAR(MAX) NOT NULL, Subject NVARCHAR(255) NOT NULL, RedirectUri VARCHAR(MAX), ValidTo DATETIME2, Created DATETIME2)");
                    connection.Execute("CREATE TABLE AuthorizationCodes (Id bigint NOT NULL PRIMARY KEY IDENTITY(1,1), ClientId VARCHAR(255) NOT NULL, Ticket VARCHAR(MAX) NOT NULL, Code VARCHAR(MAX) NOT NULL, Subject NVARCHAR(255) NOT NULL, Scope NVARCHAR(MAX), RedirectUri VARCHAR(MAX), ValidTo DATETIME2, Created DATETIME2)");
                }
                finally
                {
                    connection.Close();
                }
            }
        }

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

            this.tokenManager = new TokenManager(
                LogManager.GetLogger(typeof(SqlServerTokenRepositoryTests)),
                userManager.Object,
                new PrincipalProvider(new PBKDF2CryptoProvider()),
                new PBKDF2CryptoProvider(),
                new SqlServerTokenRepository(
                    new SqlServerTokenRepositoryConfiguration(
                        this.instance.CreateConnectionStringBuilder().ToString(),
                        this.databaseName)));
        }

        [Test]
        public async void AuthenticateAuthorizationCode_WhenGivenValidIdentity_ReturnsAuthenticatedIdentity()
        {
            var code =
                await
                this.tokenManager.CreateAuthorizationCodeAsync(
                    new SentinelPrincipal(
                    new SentinelIdentity(AuthenticationType.OAuth, new SentinelClaim(ClaimTypes.Name, "azzlack"), new SentinelClaim(ClaimType.Client, "NUnit"))),
                    TimeSpan.FromMinutes(5),
                    "http://localhost");

            Console.WriteLine("Code: {0}", code);

            Assert.IsNotNullOrEmpty(code);

            var user = await this.tokenManager.AuthenticateAuthorizationCodeAsync("http://localhost", code);

            Assert.IsTrue(user.Identity.IsAuthenticated);
        }

        [Test]
        public async void AuthenticateAccessToken_WhenGivenValidIdentity_ReturnsAuthenticatedIdentity()
        {
            var token =
                await
                this.tokenManager.CreateAccessTokenAsync(
                    new SentinelPrincipal(
                    new SentinelIdentity(AuthenticationType.OAuth, new SentinelClaim(ClaimTypes.Name, "azzlack"), new SentinelClaim(ClaimType.Client, "NUnit"))),
                    TimeSpan.FromHours(1),
                    "NUnit",
                    "http://localhost");

            Console.WriteLine("Code: {0}", token);

            Assert.IsNotNullOrEmpty(token);

            var user = await this.tokenManager.AuthenticateAccessTokenAsync(token);

            Assert.IsTrue(user.Identity.IsAuthenticated);
        }

        [Test]
        public async void AuthenticateRefreshToken_WhenGivenValidIdentity_ReturnsAuthenticatedIdentity()
        {
            var token =
                await
                this.tokenManager.CreateRefreshTokenAsync(
                    new SentinelPrincipal(
                    new SentinelIdentity(AuthenticationType.OAuth, new SentinelClaim(ClaimTypes.Name, "azzlack"), new SentinelClaim(ClaimType.Client, "NUnit"))),
                    TimeSpan.FromDays(90),
                    "NUnit",
                    "http://localhost");

            Console.WriteLine("Code: {0}", token);

            Assert.IsNotNullOrEmpty(token);

            var user = await this.tokenManager.AuthenticateRefreshTokenAsync("NUnit", token, "http://localhost");

            Assert.IsTrue(user.Identity.IsAuthenticated);
        }

        /// <summary>
        /// The test fixture tear down.
        /// </summary>
        [TestFixtureTearDown]
        public void TestFixtureTearDown()
        {
            if (this.instance != null && this.instance.IsRunning)
            {
                // Delete database
                using (var connection = this.instance.CreateConnection())
                {
                    connection.Open();

                    try
                    {
                        connection.Execute("DROP DATABASE " + this.databaseName);
                    }
                    finally
                    {
                        connection.Close();
                    }
                }

                this.instance.Stop();
            }
        }
    } 
}