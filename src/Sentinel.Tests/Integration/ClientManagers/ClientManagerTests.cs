namespace Sentinel.Tests.Integration.ClientManagers
{
    using NUnit.Framework;
    using Sentinel.OAuth.Core.Interfaces.Managers;
    using System;
    using System.Diagnostics;

    using Sentinel.OAuth.Core.Models;

    public abstract class ClientManagerTests
    {
        private Stopwatch testFixtureStopwatch;

        private Stopwatch testStopwatch;

        public IClientManager ClientManager { get; set; }

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
        public async void Authenticate_WhenGivenValidClientIdAndScope_ReturnsAuthenticatedIdentity()
        {
            var user = await this.ClientManager.AuthenticateClientAsync("NUnit", new string[0]);

            Assert.IsTrue(user.Identity.IsAuthenticated, "The client was not authenticated");
        }

        [Test]
        public async void Authenticate_WhenGivenInvalidClientIdAndScope_ReturnsNotAuthenticatedIdentity()
        {
            var user = await this.ClientManager.AuthenticateClientAsync("NUnit56", new string[0]);

            Assert.IsFalse(user.Identity.IsAuthenticated, "The client was authenticated");
        }

        [Test]
        public async void Authenticate_WhenGivenValidClientIdAndRedirectUri_ReturnsAuthenticatedIdentity()
        {
            var user = await this.ClientManager.AuthenticateClientAsync("NUnit", "http://localhost");

            Assert.IsTrue(user.Identity.IsAuthenticated, "The client was not authenticated");
        }

        [Test]
        public async void Authenticate_WhenGivenValidClientIdAndInvalidRedirectUri_ReturnsNotAuthenticatedIdentity()
        {
            var user = await this.ClientManager.AuthenticateClientAsync("NUnit", "http://localhostbcs");

            Assert.IsFalse(user.Identity.IsAuthenticated, "The client was authenticated");
        }

        [Test]
        public async void Authenticate_WhenGivenValidClientIdAndSecret_ReturnsAuthenticatedIdentity()
        {
            var user = await this.ClientManager.AuthenticateClientCredentialsAsync("NUnit", "aabbccddee");

            Assert.IsTrue(user.Identity.IsAuthenticated, "The client was not authenticated");
        }

        [Test]
        public async void Authenticate_WhenGivenDisabledClientId_ReturnsNotAuthenticatedIdentity()
        {
            var user = await this.ClientManager.AuthenticateClientCredentialsAsync("NUnit2", "aabbccddee");

            Assert.IsFalse(user.Identity.IsAuthenticated, "The client was authenticated");
        }

        [Test]
        public async void Authenticate_WhenGivenInvalidClientIdAndSecret_ReturnsNotAuthenticatedIdentity()
        {
            var user = await this.ClientManager.AuthenticateClientCredentialsAsync("NUnit", "xyz");

            Assert.IsFalse(user.Identity.IsAuthenticated, "The client was authenticated");
        }

        [TestCase("NUnit", "aabbccddee")]
        public async void AuthenticateClientWithApiKeyAsync_WhenGivenValidBasicAuthenticationDigest_ReturnsAuthenticatedIdentity(string username, string password)
        {
            var client = await this.ClientManager.AuthenticateClientCredentialsAsync(new BasicAuthenticationDigest(username, password));

            Assert.IsTrue(client.Identity.IsAuthenticated, "The client was not authenticated");
        }

        [TestCase("NUnit", "")]
        [TestCase("NUnit", "eeddccbbaa")]
        public async void AuthenticateClientWithApiKeyAsync_WhenGivenInvalidBasicAuthenticationDigest_ReturnsNotAuthenticatedIdentity(string username, string password)
        {
            var client = await this.ClientManager.AuthenticateClientCredentialsAsync(new BasicAuthenticationDigest(username, password));

            Assert.IsFalse(client.Identity.IsAuthenticated, "The client was authenticated");
        }
    }
}