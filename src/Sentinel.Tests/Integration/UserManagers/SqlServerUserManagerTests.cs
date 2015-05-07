namespace Sentinel.Tests.Integration.UserManagers
{
    using System;
    using System.Data;
    using System.Data.SqlLocalDb;

    using Dapper;

    using NUnit.Framework;

    using Sentinel.OAuth.Core.Interfaces.Managers;
    using Sentinel.OAuth.Implementation;
    using Sentinel.OAuth.UserManagers.SqlServerUserManager.Implementation;
    using Sentinel.OAuth.UserManagers.SqlServerUserManager.Models;

    [TestFixture]
    [Category("Integration")]
    public class SqlServerUserManagerTests
    {
        private TemporarySqlLocalDbInstance instance;

        private string databaseName;

        private IUserManager userManager;

        [TestFixtureSetUp]
        public void TestFixtureSetUp()
        {
            if (!SqlLocalDbApi.IsLocalDBInstalled())
            {
                throw new Exception("LocalDB is not installed!");
            }

            this.databaseName = "SqlServerUserManagerTests_" + Guid.NewGuid().ToString("N");

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
                    connection.Execute("CREATE DATABASE " + this.databaseName);
                    connection.Execute("USE " + this.databaseName);
                    connection.Execute("CREATE TABLE Users (Username VARCHAR(255) NOT NULL PRIMARY KEY, Password VARCHAR(MAX) NOT NULL, FirstName NVARCHAR(255) NOT NULL, LastName NVARCHAR(255) NOT NULL, LastLogin DATETIME2)");
                    connection.Execute("INSERT INTO Users (Username, Password, FirstName, LastName) VALUES ('azzlack', '10000:gW7zpVeugKl8IFu7TcpPskcgQjy4185eAwBk9fFlZK6JNd1I45tLyCYtJrzWzE+kVCUP7lMSY8o808EjUgfavBzYU/ZtWypcdCdCJ0BMfMcf8Mk+XIYQCQLiFpt9Rjrf5mAY86NuveUtd1yBdPjxX5neMXEtquNYhu9I6iyzcN4=:Lk2ZkpmTDkNtO/tsB/GskMppdAX2bXehP+ED4oLis0AAv3Q1VeI8KL0SxIIWdxjKH0NJKZ6qniRFkfZKZRS2hS4SB8oyB34u/jyUlmv+RZGZSt9nJ9FYJn1percd/yFA7sSQOpkGljJ6OTwdthe0Bw0A/8qlKHbO2y2M5BFgYHY=', 'Ove', 'Andersen')");
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
            this.userManager = new SqlServerUserManager(new SqlServerUserManagerConfiguration(this.instance.CreateConnectionStringBuilder().ToString(), this.databaseName), new PBKDF2CryptoProvider());
        }

        [Test]
        public async void Authenticate_WhenGivenValidUsernameAndPassword_ReturnsAuthenticatedIdentity()
        {
            var user = await this.userManager.AuthenticateUserWithPasswordAsync("azzlack", "aabbccddee");

            Assert.IsTrue(user.Identity.IsAuthenticated, "The user was not authenticated");
        }

        [Test]
        public async void Authenticate_WhenGivenInvalidUsernameAndPassword_ReturnsNotAuthenticatedIdentity()
        {
            var user = await this.userManager.AuthenticateUserWithPasswordAsync("azzlack", "xyz");

            Assert.IsFalse(user.Identity.IsAuthenticated, "The user was authenticated");
        }

        [TestFixtureTearDown]
        public void TestFixtureTearDown()
        {
            if (this.instance != null)
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
                
                this.instance.Dispose();
            }
        }
    }
}