namespace Sentinel.Tests.Unit
{
    using System;

    using Microsoft.Owin;

    using Moq;

    using NUnit.Framework;

    using Sentinel.OAuth.Client.Mvc5.Extensions;

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
    }
}