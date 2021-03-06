﻿namespace Sentinel.Tests.Integration.TokenManagers
{
    using Common.Logging;
    using Dapper;
    using Moq;
    using NUnit.Framework;
    using Sentinel.OAuth.ClientManagers.SqlServerClientRepository.Implementation;
    using Sentinel.OAuth.Core.Constants.Identity;
    using Sentinel.OAuth.Core.Interfaces.Managers;
    using Sentinel.OAuth.Implementation.Managers;
    using Sentinel.OAuth.Implementation.Providers;
    using Sentinel.OAuth.Models.Identity;
    using Sentinel.OAuth.TokenManagers.SqlServerTokenRepository.Implementation;
    using System;
    using System.Data;
    using System.Data.SqlLocalDb;
    using System.Security.Claims;

    using Sentinel.OAuth.Core.Constants;

    [TestFixture]
    [Category("Integration")]
    public class SqlServerTokenManagerTests : TokenManagerTests
    {
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

            this.databaseName = "SqlServerTokenManagerTests" + Guid.NewGuid().ToString("N");

            // Configure dapper to support datetime2
            SqlMapper.AddTypeMap(typeof(DateTime), DbType.DateTime2);

            // Create test instance
            this.instance = TemporarySqlLocalDbInstance.Create(deleteFiles: true);

            // Seed test data
            using (var connection = this.instance.CreateConnection())
            {
                connection.Open();

                try
                {
                    connection.Execute($"CREATE DATABASE [{this.databaseName}]");
                    connection.Execute($"USE [{this.databaseName}]");
                    connection.Execute("CREATE TABLE AccessTokens (Id bigint NOT NULL PRIMARY KEY IDENTITY(1,1), ClientId VARCHAR(255) NOT NULL, Ticket VARCHAR(MAX) NOT NULL, Token VARCHAR(MAX) NOT NULL, Subject NVARCHAR(255) NOT NULL, RedirectUri NVARCHAR(2083), Scope NVARCHAR(MAX), ValidTo DATETIME2, Created DATETIME2)");
                    connection.Execute("CREATE TABLE RefreshTokens (Id bigint NOT NULL PRIMARY KEY IDENTITY(1,1), ClientId VARCHAR(255) NOT NULL, Token VARCHAR(MAX) NOT NULL, Subject NVARCHAR(255) NOT NULL, RedirectUri NVARCHAR(2083), Scope NVARCHAR(MAX), ValidTo DATETIME2, Created DATETIME2)");
                    connection.Execute("CREATE TABLE AuthorizationCodes (Id bigint NOT NULL PRIMARY KEY IDENTITY(1,1), ClientId VARCHAR(255) NOT NULL, Ticket VARCHAR(MAX) NOT NULL, Code VARCHAR(MAX) NOT NULL, Subject NVARCHAR(255) NOT NULL, Scope NVARCHAR(MAX), RedirectUri NVARCHAR(2083), ValidTo DATETIME2, Created DATETIME2)");
                }
                finally
                {
                    connection.Close();
                }
            }

            base.TestFixtureSetUp();
        }

        [SetUp]
        public override void SetUp()
        {
            var connectionStringBuilder = this.instance.CreateConnectionStringBuilder();
            connectionStringBuilder.SetInitialCatalogName(this.databaseName);

            var principalProvider = new PrincipalProvider(new PBKDF2CryptoProvider());
            var tokenRepository = new SqlServerTokenRepository(connectionStringBuilder.ToString());

            this.TokenManager = new TokenManager(
                LogManager.GetLogger(typeof(SqlServerTokenManagerTests)),
                principalProvider,
                new SentinelTokenProvider(new SHA2CryptoProvider(HashAlgorithm.SHA256), principalProvider),
                tokenRepository);

            base.SetUp();
        }

        /// <summary>
        /// The test fixture tear down.
        /// </summary>
        [TestFixtureTearDown]
        public override void TestFixtureTearDown()
        {
            this.instance?.Dispose();

            base.TestFixtureTearDown();
        }
    }
}