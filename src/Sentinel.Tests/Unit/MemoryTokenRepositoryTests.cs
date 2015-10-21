namespace Sentinel.Tests.Unit
{

    using NUnit.Framework;
    using Sentinel.OAuth.Implementation;
    using Sentinel.OAuth.Implementation.Repositories;

    [TestFixture]
    [Category("Unit")]
    public class MemoryTokenRepositoryTests : TokenRepositoryTests
    {
        [SetUp]
        public override void SetUp()
        {
            this.TokenRepository = new MemoryTokenRepository();

            base.SetUp();
        }
    }
}