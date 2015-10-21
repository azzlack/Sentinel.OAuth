namespace Sentinel.Tests.Unit
{
    using Dapper;
    using NUnit.Framework;
    using Sentinel.OAuth.TokenManagers.SqlServerTokenRepository.Implementation;
    using Sentinel.OAuth.TokenManagers.SqlServerTokenRepository.Models;
    using System;
    using System.Data;
    using System.Data.SqlLocalDb;

    [TestFixture]
    [Category("Unit")]
    public class SqlTokenRepositoryTests : TokenRepositoryTests
    {
        /// <summary>The instance.</summary>
        private TemporarySqlLocalDbInstance instance;

        private string databaseName;

        /// <summary>
        /// The test fixture set up.
        /// </summary>
        /// <exception cref="Exception">
        /// </exception>
        [TestFixtureSetUp]
        public override void TestFixtureSetUp()
        {
            if (!SqlLocalDbApi.IsLocalDBInstalled())
            {
                throw new Exception("LocalDB is not installed!");
            }

            this.databaseName = "SqlTokenRepositoryTests" + Guid.NewGuid().ToString("N");

            // Configure dapper to support datetime2
            SqlMapper.AddTypeMap(typeof(DateTime), DbType.DateTime2);

            // Create test instance
            this.instance = TemporarySqlLocalDbInstance.Create(true);

            // Seed test data
            using (var connection = this.instance.CreateConnection())
            {
                connection.Open();

                connection.Execute($"CREATE DATABASE [{this.databaseName}]");
                connection.Execute($"USE [{this.databaseName}]");
                connection.Execute("CREATE TABLE AccessTokens (Id bigint NOT NULL PRIMARY KEY IDENTITY(1,1), ClientId VARCHAR(255) NOT NULL, Ticket VARCHAR(MAX) NOT NULL, Token VARCHAR(MAX) NOT NULL, Subject NVARCHAR(255) NOT NULL, RedirectUri VARCHAR(MAX), Scope NVARCHAR(MAX), ValidTo DATETIMEOFFSET, Created DATETIMEOFFSET)");
                connection.Execute("CREATE TABLE RefreshTokens (Id bigint NOT NULL PRIMARY KEY IDENTITY(1,1), ClientId VARCHAR(255) NOT NULL, Token VARCHAR(MAX) NOT NULL, Subject NVARCHAR(255) NOT NULL, RedirectUri VARCHAR(MAX), Scope NVARCHAR(MAX), ValidTo DATETIMEOFFSET, Created DATETIMEOFFSET)");
                connection.Execute("CREATE TABLE AuthorizationCodes (Id bigint NOT NULL PRIMARY KEY IDENTITY(1,1), ClientId VARCHAR(255) NOT NULL, Ticket VARCHAR(MAX) NOT NULL, Code VARCHAR(MAX) NOT NULL, Subject NVARCHAR(255) NOT NULL, Scope NVARCHAR(MAX), RedirectUri VARCHAR(MAX), ValidTo DATETIMEOFFSET, Created DATETIMEOFFSET)");
            }

            base.TestFixtureSetUp();
        }

        [SetUp]
        public override void SetUp()
        {
            var connectionStringBuilder = this.instance.CreateConnectionStringBuilder();
            connectionStringBuilder.InitialCatalog = this.databaseName;

            this.TokenRepository =
                new SqlServerTokenRepository(
                    new SqlServerTokenRepositoryConfiguration(
                        connectionStringBuilder.ToString()));

            base.SetUp();
        }

        /// <summary>
        /// The test fixture tear down.
        /// </summary>
        [TestFixtureTearDown]
        public override void TestFixtureTearDown()
        {
            if (this.instance != null)
            {
                this.instance.Dispose();
            }

            base.TestFixtureTearDown();
        }
    }
}