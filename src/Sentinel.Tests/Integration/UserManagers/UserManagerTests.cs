namespace Sentinel.Tests.Integration.UserManagers
{
    using NUnit.Framework;
    using Sentinel.OAuth.Core.Interfaces.Managers;
    using System;
    using System.Diagnostics;

    using Sentinel.OAuth.Core.Models;

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

        [TestCase("azzlack", "PFJTQUtleVZhbHVlPjxNb2R1bHVzPnlidFpyM0pWS0p1L2hlUFMrV0Zla1kyYmRYVDlJMU1MeHZheTlIMW9IenRwRmI4QzJtQmUzY1EzVDhjUzE0ajJ4bk9lRkt2YVZ4Ukw5S2ozd0tOL1B3PT08L01vZHVsdXM+PEV4cG9uZW50PkFRQUI8L0V4cG9uZW50PjxQPjZTRHRuS2tpamozZC9pdExYaUZtb0NDR050VWxhRTRZV2xsOXFHaXlSb2s9PC9QPjxRPjNZWGl0TmhYRkk0MTZOQ29hU2RpUldKSW5QQUU0aGYzdkVoWE5GOWFwWWM9PC9RPjxEUD55aXgvUkNROXpvT0N1SUROWExXMHJWdG5hYmdSTjlLNk5laDBIQStudzVrPTwvRFA+PERRPm9MUllXMG4zSW5wb3NaVnVGNXJ5dDlNdFNtejFuZkExVU9wS0dUeHp6bEU9PC9EUT48SW52ZXJzZVE+Qmx0UiszUTdKVGFnOHJDTVdIOXlNekE2UFE3K1dpWWR4T0o3eHBKNmF3RT08L0ludmVyc2VRPjxEPlRybVI0T0Y5OFRpQ3IvWCtKYnNGWkVqK1k0S1JyUURpSmpXdEZiT0ErRHFPTkx0cXMxWnNDMzBpZyt2LzN3ZitWTWNRK3FFRnN0bGhFOTlaWFN5cDZRPT08L0Q+PC9SU0FLZXlWYWx1ZT4=")]
        public async void AuthenticateUserWithApiKeyAsync_WhenGivenValidBasicAuthenticationDigest_ReturnsAuthenticatedIdentity(string username, string password)
        {
            var client = await this.UserManager.AuthenticateUserWithApiKeyAsync(new BasicAuthenticationDigest(username, password));

            Assert.IsTrue(client.Identity.IsAuthenticated, "The user was not authenticated");
        }

        [TestCase("azzlack", "")]
        [TestCase("azzlack", "aabbccddee")]
        [TestCase("azzlack", "PFJTQUtleVZhbHVlPjxNb2R1bHVzPjNST202Y3hjaG5yZ2xpSzNwS1R6VDZ6cWQxVklpZUUzWVU1cWdyZWFkT3QwVHdjNHhGNncvUkJVWmh2ZVgxWUdCNjZEdC9aTWhad3Y5Z3B1eXhrTU93PT08L01vZHVsdXM+PEV4cG9uZW50PkFRQUI8L0V4cG9uZW50PjxQPjdRS2ZmVHZsellnQURzdmhlZzVlak1HeFNITWhTUGdMUWhXbVk0ZWNhWTg9PC9QPjxRPjdzbzJucjYrL0krUi8rbnZhUFNNTVJESTErMlFWZXd0WlFsV0o2ZVFwSlU9PC9RPjxEUD5XcWtQTXd0dmV6QlR2VlUxMmNlWFdVWmFOemw2K1B1UTZ1VjNNVWxWaG5jPTwvRFA+PERRPlRXNE9wZzBPR3hGbTgwZmxGUEJ2WVIyak1ybGEyekc1U3BEcmVmSlE2YjA9PC9EUT48SW52ZXJzZVE+Y1R6b2NaYXAvSm54OUVkQmtWOHJYdjdVWlN3MWRLT00vYmt1ZFFRbUVMbz08L0ludmVyc2VRPjxEPkhqUmpKNnBPTWVsejZjOVFlK1ExZ2Z0RUJZM1hYVTh4Kzg5MDZlc2Y1VDFOSXV5RzNHRFQxU01OYm1xd01RNVBUVVdkRlAxREk3dXZwSUkzU01SVGNRPT08L0Q+PC9SU0FLZXlWYWx1ZT4=")]
        public async void AuthenticateUserWithApiKeyAsync_WhenGivenInvalidBasicAuthenticationDigest_ReturnsNotAuthenticatedIdentity(string username, string password)
        {
            var client = await this.UserManager.AuthenticateUserWithApiKeyAsync(new BasicAuthenticationDigest(username, password));

            Assert.IsFalse(client.Identity.IsAuthenticated, "The user was authenticated");
        }

        [TestCase("azzlack", "PFJTQUtleVZhbHVlPjxNb2R1bHVzPnlidFpyM0pWS0p1L2hlUFMrV0Zla1kyYmRYVDlJMU1MeHZheTlIMW9IenRwRmI4QzJtQmUzY1EzVDhjUzE0ajJ4bk9lRkt2YVZ4Ukw5S2ozd0tOL1B3PT08L01vZHVsdXM+PEV4cG9uZW50PkFRQUI8L0V4cG9uZW50PjxQPjZTRHRuS2tpamozZC9pdExYaUZtb0NDR050VWxhRTRZV2xsOXFHaXlSb2s9PC9QPjxRPjNZWGl0TmhYRkk0MTZOQ29hU2RpUldKSW5QQUU0aGYzdkVoWE5GOWFwWWM9PC9RPjxEUD55aXgvUkNROXpvT0N1SUROWExXMHJWdG5hYmdSTjlLNk5laDBIQStudzVrPTwvRFA+PERRPm9MUllXMG4zSW5wb3NaVnVGNXJ5dDlNdFNtejFuZkExVU9wS0dUeHp6bEU9PC9EUT48SW52ZXJzZVE+Qmx0UiszUTdKVGFnOHJDTVdIOXlNekE2UFE3K1dpWWR4T0o3eHBKNmF3RT08L0ludmVyc2VRPjxEPlRybVI0T0Y5OFRpQ3IvWCtKYnNGWkVqK1k0S1JyUURpSmpXdEZiT0ErRHFPTkx0cXMxWnNDMzBpZyt2LzN3ZitWTWNRK3FFRnN0bGhFOTlaWFN5cDZRPT08L0Q+PC9SU0FLZXlWYWx1ZT4=")]
        public async void AuthenticateUserWithApiKeyAsync_WhenGivenValidApiKeyAuthenticationDigest_ReturnsAuthenticatedIdentity(string username, string password)
        {
            var user = await this.UserManager.AuthenticateUserWithApiKeyAsync(new ApiKeyAuthenticationDigest(username, password, "", new Uri(""), 0, "", ""));

            Assert.IsTrue(user.Identity.IsAuthenticated, "The user was not authenticated");
        }

        [TestCase("azzlack", "")]
        [TestCase("azzlack", "aabbccddee")]
        [TestCase("azzlack", "PFJTQUtleVZhbHVlPjxNb2R1bHVzPjNST202Y3hjaG5yZ2xpSzNwS1R6VDZ6cWQxVklpZUUzWVU1cWdyZWFkT3QwVHdjNHhGNncvUkJVWmh2ZVgxWUdCNjZEdC9aTWhad3Y5Z3B1eXhrTU93PT08L01vZHVsdXM+PEV4cG9uZW50PkFRQUI8L0V4cG9uZW50PjxQPjdRS2ZmVHZsellnQURzdmhlZzVlak1HeFNITWhTUGdMUWhXbVk0ZWNhWTg9PC9QPjxRPjdzbzJucjYrL0krUi8rbnZhUFNNTVJESTErMlFWZXd0WlFsV0o2ZVFwSlU9PC9RPjxEUD5XcWtQTXd0dmV6QlR2VlUxMmNlWFdVWmFOemw2K1B1UTZ1VjNNVWxWaG5jPTwvRFA+PERRPlRXNE9wZzBPR3hGbTgwZmxGUEJ2WVIyak1ybGEyekc1U3BEcmVmSlE2YjA9PC9EUT48SW52ZXJzZVE+Y1R6b2NaYXAvSm54OUVkQmtWOHJYdjdVWlN3MWRLT00vYmt1ZFFRbUVMbz08L0ludmVyc2VRPjxEPkhqUmpKNnBPTWVsejZjOVFlK1ExZ2Z0RUJZM1hYVTh4Kzg5MDZlc2Y1VDFOSXV5RzNHRFQxU01OYm1xd01RNVBUVVdkRlAxREk3dXZwSUkzU01SVGNRPT08L0Q+PC9SU0FLZXlWYWx1ZT4=")]
        public async void AuthenticateUserWithApiKeyAsync_WhenGivenInvalidApiKeyAuthenticationDigest_ReturnsNotAuthenticatedIdentity(string username, string password)
        {
            var user = await this.UserManager.AuthenticateUserWithApiKeyAsync(new ApiKeyAuthenticationDigest(username, password, "", new Uri(""), 0, "", ""));

            Assert.IsFalse(user.Identity.IsAuthenticated, "The user was authenticated");
        }
    }
}