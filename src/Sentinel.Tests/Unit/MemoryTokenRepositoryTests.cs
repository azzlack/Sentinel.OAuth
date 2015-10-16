namespace Sentinel.Tests.Unit
{

    using NUnit.Framework;
    using Sentinel.OAuth.Implementation;

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