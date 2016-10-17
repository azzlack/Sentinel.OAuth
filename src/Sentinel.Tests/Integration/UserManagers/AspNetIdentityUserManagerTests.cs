namespace Sentinel.Tests.Integration.UserManagers
{
    using System;
    using System.Data;
    using System.Data.Entity;
    using System.Data.SqlLocalDb;

    using Microsoft.AspNet.Identity;
    using Microsoft.AspNet.Identity.EntityFramework;

    using NUnit.Framework;

    using Sentinel.OAuth.Core.Interfaces.Managers;
    using Sentinel.OAuth.Implementation.Providers;
    using Sentinel.OAuth.UserManagers.AspNetIdentityUserManager;
    using Sentinel.OAuth.UserManagers.AspNetIdentityUserManager.Implementation;
    using Sentinel.OAuth.UserManagers.SqlServerUserRepository.Implementation;

    using User = Sentinel.OAuth.UserManagers.AspNetIdentityUserManager.Models.User;

    [TestFixture]
    [Category("Integration")]
    public class AspNetIdentityUserManagerTests
    {
        private string connectionString;

        private IUserManager userManager;

        private TemporarySqlLocalDbInstance instance;

        [TestFixtureSetUp]
        public void TestFixtureSetUp()
        {
            var localDb = new SqlLocalDbApiWrapper();

            if (!localDb.IsLocalDBInstalled())
            {
                throw new Exception("LocalDB is not installed!");
            }

            this.instance = TemporarySqlLocalDbInstance.Create(deleteFiles: true);

            // Initialize database
            var strategy = new DropCreateDatabaseAlways<SentinelContext>();
            Database.SetInitializer(strategy);

            var builder = this.instance.CreateConnectionStringBuilder();

            // Update the connection string to specify the name of the database
            // and its physical location to the current application directory
            builder.SetInitialCatalogName("SentinelAuth");
            builder.SetPhysicalFileName(@".\SentinelAuth.mdf");

            this.connectionString = builder.ConnectionString;

            using (var context = new SentinelContext(this.connectionString))
            {
                context.Database.Initialize(true);
            }
        }

        [SetUp]
        public void SetUp()
        {
            this.userManager = new AspNetIdentityUserManager(new UserStore<User>(new SentinelContext(this.connectionString)), new SqlServerUserApiKeyRepository(this.connectionString), new PBKDF2CryptoProvider(), new AsymmetricCryptoProvider());

            // Add a user to the database
            ((UserManager<User>)this.userManager).Create(new User() { UserName = "azzlack", FirstName = "Ove", LastName = "Andersen" }, "aabbccddee");
        }

        [Test]
        public async void Authenticate_WhenGivenValidUsernameAndPassword_ReturnsAuthenticatedIdentity()
        {
            var user = await this.userManager.AuthenticateUserWithPasswordAsync("azzlack", "aabbccddee");

            Assert.IsTrue(user.Identity.IsAuthenticated, "The user was not authenticated");

            Console.WriteLine("Claims:");
            foreach (var claim in user.Identity.Claims)
            {
                Console.WriteLine("{0}: {1}", claim.Type, claim.Value);
            }
        }

        [Test]
        public async void Authenticate_WhenGivenInvalidUsernameAndPassword_ReturnsNotAuthenticatedIdentity()
        {
            var user = await this.userManager.AuthenticateUserWithPasswordAsync("azzlack", "xyz");

            Assert.IsFalse(user.Identity.IsAuthenticated, "The user was authenticated");
        }

        [Test]
        public async void Authenticate_WhenGivenValidUsername_ReturnsAuthenticatedIdentity()
        {
            var user = await this.userManager.AuthenticateUserAsync("azzlack");

            Assert.IsTrue(user.Identity.IsAuthenticated, "The user was not authenticated");

            Console.WriteLine("Claims:");
            foreach (var claim in user.Identity.Claims)
            {
                Console.WriteLine("{0}: {1}", claim.Type, claim.Value);
            }
        }

        [Test]
        public async void Authenticate_WhenGivenInvalidUsername_ReturnsNotAuthenticatedIdentity()
        {
            var user = await this.userManager.AuthenticateUserAsync("xyz");

            Assert.IsFalse(user.Identity.IsAuthenticated, "The user was authenticated");
        }

        [TestFixtureTearDown]
        public void TestFixtureTearDown()
        {
            this.instance?.Dispose();
        }
    }
}