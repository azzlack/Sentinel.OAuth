namespace Sentinel.Tests.Integration.UserManagers
{
    using NUnit.Framework;
    using Sentinel.OAuth.Core.Interfaces.Managers;
    using System;
    using System.Diagnostics;

    public abstract class UserManagerTests
    {
        private Stopwatch testFixtureStopwatch;

        private Stopwatch testStopwatch;

        public IUserManager UserManager { get; set; }

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
            Console.WriteLine($"##teamcity[buildStatisticValue key='{this.GetType().Name}' value='{this.testFixtureStopwatch.ElapsedMilliseconds}']");
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
        }

        [Test]
        public async void Authenticate_WhenGivenValidUsernameAndPassword_ReturnsAuthenticatedIdentity()
        {
            var user = await this.UserManager.AuthenticateUserWithPasswordAsync("azzlack", "aabbccddee");

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
            var user = await this.UserManager.AuthenticateUserWithPasswordAsync("azzlack", "xyz");

            Assert.IsFalse(user.Identity.IsAuthenticated, "The user was authenticated");
        }

        [Test]
        public async void Authenticate_WhenGivenValidUsername_ReturnsAuthenticatedIdentity()
        {
            var user = await this.UserManager.AuthenticateUserAsync("azzlack");

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
            var user = await this.UserManager.AuthenticateUserAsync("xyz");

            Assert.IsFalse(user.Identity.IsAuthenticated, "The user was authenticated");
        }
    }
}