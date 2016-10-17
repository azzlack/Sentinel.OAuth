namespace Sentinel.Tests.Unit
{
    using System;

    using Microsoft.Owin;

    using Moq;

    using NUnit.Framework;

    using Sentinel.OAuth.Extensions;

    [TestFixture]
    [Category("Unit")]
    public class OwinRequestExtensionsTests
    {
        [TestCase("/something/test")]
        [TestCase("/#something/test")]
        [TestCase("http://localhost/something/test")]
        public void IsLocalUrl_WhenGivenValidUrl_ReturnsTrue(string url)
        {
            var request = new Mock<IOwinRequest>();
            request.Setup(x => x.Uri).Returns(() => new Uri("http://localhost"));

            Assert.IsTrue(request.Object.IsLocalUrl(url));
        }

        [TestCase("something/test")]
        [TestCase("#something/test")]
        [TestCase("http://something/something/test")]
        [TestCase("https://localhost/something/test")]
        public void IsLocalUrl_WhenGivenInvalidUrl_ReturnsFalse(string url)
        {
            var request = new Mock<IOwinRequest>();
            request.Setup(x => x.Uri).Returns(() => new Uri("http://localhost"));

            Assert.IsFalse(request.Object.IsLocalUrl(url));
        }

        [TestCase("http://localhost/something/test", "http://localhost/something/test")]
        [TestCase("http://localhost/something/test", "/something/test")]
        [TestCase("http://localhost/something/test?qe=1", "/something/test?qe=1")]

        public void IsSameUrl_WhenGivenEqualUrl_ReturnsTrue(string left, string right)
        {
            var request = new Mock<IOwinRequest>();
            request.Setup(x => x.Uri).Returns(() => new Uri(left));

            Assert.IsTrue(request.Object.IsSameUrl(right));
        }

        [TestCase("http://localhost/something/test", "http://localhost/something/test2")]
        [TestCase("http://localhost/something/test", "/something/test2")]
        [TestCase("http://localhost/something/test", "/something/test?eq=1")]

        public void IsSameUrl_WhenGivenNonEqualUrl_ReturnsFalse(string left, string right)
        {
            var request = new Mock<IOwinRequest>();
            request.Setup(x => x.Uri).Returns(() => new Uri(left));

            Assert.IsFalse(request.Object.IsSameUrl(right));
        }
    }
}