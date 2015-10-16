namespace Sentinel.Tests.Unit
{

    using NUnit.Framework;

    using Raven.Client.Embedded;

    using Sentinel.OAuth.TokenManagers.RavenDbTokenRepository.Implementation;
    using Sentinel.OAuth.TokenManagers.RavenDbTokenRepository.Models;

    [TestFixture]
    [Category("Unit")]
    public class RavenDbTokenRepositoryTests : TokenRepositoryTests
    {
        [SetUp]
        public override void SetUp()
        {
            this.TokenRepository = new RavenDbTokenRepository(new RavenDbTokenRepositoryConfiguration(new EmbeddableDocumentStore() { RunInMemory = true }));

            base.SetUp();
        }
    }
}