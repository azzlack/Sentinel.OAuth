namespace Sentinel.Tests.Integration.ClientManagers
{
    using System;
    using System.Data;
    using System.Data.SqlLocalDb;

    using Dapper;

    using NUnit.Framework;

    using Sentinel.OAuth.ClientManagers.SqlServerClientManager.Implementation;
    using Sentinel.OAuth.ClientManagers.SqlServerClientManager.Models;
    using Sentinel.OAuth.Core.Interfaces.Managers;
    using Sentinel.OAuth.Implementation;

    [TestFixture]
    [Category("Integration")]
    public class SqlServerClientManagerTests
    {
        private SqlLocalDbInstance instance;

        private string databaseName;

        private IClientManager clientManager;

        [TestFixtureSetUp]
        public void TestFixtureSetUp()
        {
            var localDb = new SqlLocalDbApiWrapper();

            if (!localDb.IsLocalDBInstalled())
            {
                throw new Exception("LocalDB is not installed!");
            }

            var provider = new SqlLocalDbProvider();

            this.databaseName = "SqlServerClientManagerTests" + Guid.NewGuid().ToString("N");

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
                    connection.Execute("CREATE TABLE Clients (ClientId VARCHAR(255) NOT NULL PRIMARY KEY, ClientSecret VARCHAR(MAX) NOT NULL, RedirectUri VARCHAR(255) NOT NULL, Name NVARCHAR(255) NOT NULL, LastUsed DATETIME2, Enabled bit)");
                    connection.Execute("INSERT INTO Clients (ClientId, ClientSecret, RedirectUri, Name, Enabled) VALUES ('NUnit', '10000:gW7zpVeugKl8IFu7TcpPskcgQjy4185eAwBk9fFlZK6JNd1I45tLyCYtJrzWzE+kVCUP7lMSY8o808EjUgfavBzYU/ZtWypcdCdCJ0BMfMcf8Mk+XIYQCQLiFpt9Rjrf5mAY86NuveUtd1yBdPjxX5neMXEtquNYhu9I6iyzcN4=:Lk2ZkpmTDkNtO/tsB/GskMppdAX2bXehP+ED4oLis0AAv3Q1VeI8KL0SxIIWdxjKH0NJKZ6qniRFkfZKZRS2hS4SB8oyB34u/jyUlmv+RZGZSt9nJ9FYJn1percd/yFA7sSQOpkGljJ6OTwdthe0Bw0A/8qlKHbO2y2M5BFgYHY=', 'http://localhost', 'NUnit Test', 1)");
                    connection.Execute("INSERT INTO Clients (ClientId, ClientSecret, RedirectUri, Name) VALUES ('NUnit2', '10000:gW7zpVeugKl8IFu7TcpPskcgQjy4185eAwBk9fFlZK6JNd1I45tLyCYtJrzWzE+kVCUP7lMSY8o808EjUgfavBzYU/ZtWypcdCdCJ0BMfMcf8Mk+XIYQCQLiFpt9Rjrf5mAY86NuveUtd1yBdPjxX5neMXEtquNYhu9I6iyzcN4=:Lk2ZkpmTDkNtO/tsB/GskMppdAX2bXehP+ED4oLis0AAv3Q1VeI8KL0SxIIWdxjKH0NJKZ6qniRFkfZKZRS2hS4SB8oyB34u/jyUlmv+RZGZSt9nJ9FYJn1percd/yFA7sSQOpkGljJ6OTwdthe0Bw0A/8qlKHbO2y2M5BFgYHY=', 'http://localhost', 'NUnit2 Test')");
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
            this.clientManager = new SqlServerClientManager(new SqlServerClientManagerConfiguration(this.instance.CreateConnectionStringBuilder().ToString(), this.databaseName), new PBKDF2CryptoProvider());
        }

        [Test]
        public async void Authenticate_WhenGivenValidClientIdAndScope_ReturnsAuthenticatedIdentity()
        {
            var user = await this.clientManager.AuthenticateClientAsync("NUnit", new string[0]);

            Assert.IsTrue(user.Identity.IsAuthenticated, "The client was not authenticated");
        }

        [Test]
        public async void Authenticate_WhenGivenInvalidClientIdAndScope_ReturnsNotAuthenticatedIdentity()
        {
            var user = await this.clientManager.AuthenticateClientAsync("NUnit56", new string[0]);

            Assert.IsFalse(user.Identity.IsAuthenticated, "The client was authenticated");
        }

        [Test]
        public async void Authenticate_WhenGivenValidClientIdAndRedirectUri_ReturnsAuthenticatedIdentity()
        {
            var user = await this.clientManager.AuthenticateClientAsync("NUnit", "http://localhost");

            Assert.IsTrue(user.Identity.IsAuthenticated, "The client was not authenticated");
        }

        [Test]
        public async void Authenticate_WhenGivenValidClientIdAndInvalidRedirectUri_ReturnsNotAuthenticatedIdentity()
        {
            var user = await this.clientManager.AuthenticateClientAsync("NUnit", "http://localhostbcs");

            Assert.IsFalse(user.Identity.IsAuthenticated, "The client was authenticated");
        }

        [Test]
        public async void Authenticate_WhenGivenValidClientIdAndSecret_ReturnsAuthenticatedIdentity()
        {
            var user = await this.clientManager.AuthenticateClientCredentialsAsync("NUnit", "aabbccddee");

            Assert.IsTrue(user.Identity.IsAuthenticated, "The client was not authenticated");
        }

        [Test]
        public async void Authenticate_WhenGivenDisabledClientId_ReturnsNotAuthenticatedIdentity()
        {
            var user = await this.clientManager.AuthenticateClientCredentialsAsync("NUnit2", "aabbccddee");

            Assert.IsFalse(user.Identity.IsAuthenticated, "The client was authenticated");
        }

        [Test]
        public async void Authenticate_WhenGivenInvalidClientIdAndSecret_ReturnsNotAuthenticatedIdentity()
        {
            var user = await this.clientManager.AuthenticateClientCredentialsAsync("NUnit", "xyz");

            Assert.IsFalse(user.Identity.IsAuthenticated, "The client was authenticated");
        }

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