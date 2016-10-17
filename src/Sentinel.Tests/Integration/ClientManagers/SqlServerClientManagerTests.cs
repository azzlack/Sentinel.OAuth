namespace Sentinel.Tests.Integration.ClientManagers
{
    using Dapper;
    using NUnit.Framework;
    using Sentinel.OAuth.ClientManagers.SqlServerClientRepository.Implementation;
    using Sentinel.OAuth.Implementation.Managers;
    using Sentinel.OAuth.Implementation.Providers;
    using System;
    using System.Data;
    using System.Data.SqlLocalDb;

    [TestFixture]
    [Category("Integration")]
    public class SqlServerClientManagerTests : ClientManagerTests
    {
        private TemporarySqlLocalDbInstance instance;

        private string databaseName;

        [TestFixtureSetUp]
        public override void TestFixtureSetUp()
        {
            if (!SqlLocalDbApi.IsLocalDBInstalled())
            {
                throw new Exception("LocalDB is not installed!");
            }

            this.databaseName = "SqlServerClientManagerTests" + Guid.NewGuid().ToString("N");

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
                    connection.Execute("CREATE TABLE Clients (Id bigint NOT NULL PRIMARY KEY IDENTITY(1,1), ClientId VARCHAR(255) NOT NULL, ClientSecret VARCHAR(MAX) NOT NULL, PublicKey VARCHAR(MAX) NULL, RedirectUri NVARCHAR(2083) NOT NULL, Name NVARCHAR(255) NOT NULL, Enabled bit, LastUsed DATETIMEOFFSET, Created DATETIMEOFFSET)");
                    connection.Execute("INSERT INTO Clients (ClientId, ClientSecret, PublicKey, RedirectUri, Name, Enabled) VALUES ('NUnit', '10000:gW7zpVeugKl8IFu7TcpPskcgQjy4185eAwBk9fFlZK6JNd1I45tLyCYtJrzWzE+kVCUP7lMSY8o808EjUgfavBzYU/ZtWypcdCdCJ0BMfMcf8Mk+XIYQCQLiFpt9Rjrf5mAY86NuveUtd1yBdPjxX5neMXEtquNYhu9I6iyzcN4=:Lk2ZkpmTDkNtO/tsB/GskMppdAX2bXehP+ED4oLis0AAv3Q1VeI8KL0SxIIWdxjKH0NJKZ6qniRFkfZKZRS2hS4SB8oyB34u/jyUlmv+RZGZSt9nJ9FYJn1percd/yFA7sSQOpkGljJ6OTwdthe0Bw0A/8qlKHbO2y2M5BFgYHY=', 'PFJTQUtleVZhbHVlPjxNb2R1bHVzPnFKMEtXaXZWSjUxUWtKWGdIU1hidkxOTEJsa09rOE9uSWtvRTljU1FrRzhOZm5VYXBrWHpkTlEvb3FLZE9BSWxYK1hFMnNwN0xFcS9KRnJMaDRNblhRPT08L01vZHVsdXM+PEV4cG9uZW50PkFRQUI8L0V4cG9uZW50PjwvUlNBS2V5VmFsdWU+', 'http://localhost', 'NUnit Test', 1)");
                    connection.Execute("INSERT INTO Clients (ClientId, ClientSecret, RedirectUri, Name) VALUES ('NUnit2', '10000:gW7zpVeugKl8IFu7TcpPskcgQjy4185eAwBk9fFlZK6JNd1I45tLyCYtJrzWzE+kVCUP7lMSY8o808EjUgfavBzYU/ZtWypcdCdCJ0BMfMcf8Mk+XIYQCQLiFpt9Rjrf5mAY86NuveUtd1yBdPjxX5neMXEtquNYhu9I6iyzcN4=:Lk2ZkpmTDkNtO/tsB/GskMppdAX2bXehP+ED4oLis0AAv3Q1VeI8KL0SxIIWdxjKH0NJKZ6qniRFkfZKZRS2hS4SB8oyB34u/jyUlmv+RZGZSt9nJ9FYJn1percd/yFA7sSQOpkGljJ6OTwdthe0Bw0A/8qlKHbO2y2M5BFgYHY=', 'http://localhost', 'NUnit2 Test')");
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

            this.ClientManager = new ClientManager(
                new PBKDF2CryptoProvider(),
                new AsymmetricCryptoProvider(), 
                new SqlServerClientRepository(connectionStringBuilder.ToString()));

            base.SetUp();
        }

        [TestFixtureTearDown]
        public override void TestFixtureTearDown()
        {
            this.instance?.Dispose();

            base.TestFixtureTearDown();
        }
    }
}