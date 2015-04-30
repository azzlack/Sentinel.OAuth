namespace Sentinel.Tests.Unit
{
    using System;
    using System.Security.Cryptography;
    using System.Text;

    using NUnit.Framework;

    using Sentinel.OAuth.Implementation;

    [TestFixture]
    [Category("Unit")]
    public class PBKDF2CryptoProviderTests
    {
        [TestCase("aabbccddee")]
        public void Create_WhenGivenValidString_ReturnsHash(string text)
        {
            var factory = new PBKDF2CryptoProvider();

            var hash = factory.CreateHash(text);

            Console.WriteLine("Hash: {0}", hash);

            Assert.IsNotNullOrEmpty(hash);
            Assert.AreEqual(3, hash.Split(':').Length);
            Assert.AreEqual("10000", hash.Split(':')[0]);
        }

        [Test]
        public void Create_WhenGeneratingString_ReturnsValidHash()
        {
            var factory = new PBKDF2CryptoProvider();

            string text;
            var hash = factory.CreateHash(out text);

            Console.WriteLine("Hash: {0}", hash);

            Assert.IsNotNullOrEmpty(hash);
            Assert.AreEqual(3, hash.Split(':').Length);
            Assert.AreEqual("10000", hash.Split(':')[0]);

            var valid = factory.ValidateHash(text, hash);

            Assert.IsTrue(valid);
        }

        [TestCase(8)]
        [TestCase(48)]
        [TestCase(64)]
        [TestCase(128)]
        public void Create_WhenGeneratingStringWithSpecificLength_ReturnsValidHash(int size)
        {
            var factory = new PBKDF2CryptoProvider();

            string text;
            var hash = factory.CreateHash(out text, size);

            Console.WriteLine("Hash: {0}", hash);

            var textSize = Encoding.UTF8.GetBytes(text);

            Console.WriteLine("Text: {0}", text);
            Console.WriteLine("Text Size: {0} bits", textSize.Length * 8);

            Assert.AreEqual(size, textSize.Length * 8);

            Assert.IsNotNullOrEmpty(hash);
            Assert.AreEqual(3, hash.Split(':').Length);
            Assert.AreEqual("10000", hash.Split(':')[0]);

            var valid = factory.ValidateHash(text, hash);

            Assert.IsTrue(valid);
        }

        [TestCase(64, 64, 25000, new[] { ':' }, "aabbccddee")]
        [TestCase(48, 48, 25000, new[] { ':' }, "123")]
        [TestCase(64, 64, 25000, new[] { '|' }, "aabbccddee")]
        public void Create_WhenGivenValidString_ReturnsHash(int saltByteSize, int hashByteSize, int iterations, char[] delimiter, string text)
        {
            var factory = new PBKDF2CryptoProvider(saltByteSize, hashByteSize, iterations, delimiter);

            var hash = factory.CreateHash(text);

            Console.WriteLine("Hash: {0}", hash);

            Assert.IsNotNullOrEmpty(hash);
            Assert.AreEqual(3, hash.Split(delimiter).Length);
            Assert.AreEqual(iterations.ToString(), hash.Split(delimiter)[0]);
        }

        [TestCase("aabbccddee", "10000:WDkTBrCC3uuglikSwDwjkuSNrZ6b3IYs:c81j3L+oWFzzZ1kBt6BCbRhL48dNdBL6")]
        [TestCase("aabbccddee", "10000:E+nmwGCEObvreQhlrV4clrekiUYu877i:szblNYoQohlabb31BDMdt2KFJCRtUtp8")]
        public void Validate_WhenGivenValidCorrectTextAndHashCombination_ReturnsTrue(string text, string correctHash)
        {
            var factory = new PBKDF2CryptoProvider();

            var valid = factory.ValidateHash(text, correctHash);

            Assert.IsTrue(valid);
        }

        [TestCase(64, 64, 25000, new[] { ':' }, "aabbccddee", "25000:tUzZvrTT9NzSzUbCitZe25d1Vm71wTQjA526y1rHbq8gd/5Roq9rxNURu93A5JFOrRTvgT6urfkrLtBkW039MQ==:cFj9EgmL0p+8CWWYmnrWOsQdfWn5jCyIMHCNMmAlryvtMLUpGtWBuuERbIo4xI+4i91jZabf/CRr7Ipdb9mv0w==")]
        [TestCase(64, 64, 25000, new[] { '|' }, "aabbccddee", "25000|lErTN/RUNSvCRDQPBmQ4/Y0FL40hI7aIku47BHYeuQt0qINTeCJJ86gRE6hKHiT0UQIuXiOrsfDowqNE6tZToQ==|nbDni54XduFJJdmGiPxvr5sLn7USBN66Gad8lrLr2J+mtZT2TR1UBu9O41iXfsI0GQXx2HL0httGL6nDiL1Ncg==")]
        public void Validate_WhenGivenValidCorrectTextAndHashCombination_ReturnsTrue(int saltByteSize, int hashByteSize, int iterations, char[] delimiter, string text, string correctHash)
        {
            var factory = new PBKDF2CryptoProvider(saltByteSize, hashByteSize, iterations, delimiter);

            var valid = factory.ValidateHash(text, correctHash);

            Assert.IsTrue(valid);
        }

        [TestCase("aabbccddee", "9000:WDkTBrCC3uuglikSwDwjkuSNrZ6b3IYs:c81j3L+oWFzzZ1kBt6BCbRhL48dNdBL6")]
        [TestCase("aabbccddee", "10000:E+nmwGCEObvreQhlrV4clrfkiUYu877i:szblNYoQohlabb31BDMdt2KFJCRtUtp8")]
        public void Validate_WhenGivenValidIncorrectTextAndHashCombination_ReturnsFalse(string text, string correctHash)
        {
            var factory = new PBKDF2CryptoProvider();

            var valid = factory.ValidateHash(text, correctHash);

            Assert.IsFalse(valid);
        }


        [TestCase(64, 64, 25000, new[] { ':' }, "aabbccddee", "9000:WDkTBrCC3uuglikSwDwjkuSNrZ6b3IYs:c81j3L+oWFzzZ1kBt6BCbRhL48dNdBL6")]
        [TestCase(64, 64, 25000, new[] { '|' }, "aabbccddee", "10000|E+nmwGCEObwreQhlrV4clrekiUYu877i|szblNYoQohlabb31BDMdt2KFJCRtUtp8")]
        public void Validate_WhenGivenValidIncorrectTextAndHashCombination_ReturnsFalse(int saltByteSize, int hashByteSize, int iterations, char[] delimiter, string text, string correctHash)
        {
            var factory = new PBKDF2CryptoProvider(saltByteSize, hashByteSize, iterations, delimiter);

            var valid = factory.ValidateHash(text, correctHash);

            Assert.IsFalse(valid);
        }

        [TestCase(64, 64, 25000, new[] { '|' })]
        [TestCase(24, 24, 10000, new[] { ':' })]
        public void Validate_WhenGivenAutoGeneratedString_ReturnsValid(int saltByteSize, int hashByteSize, int iterations, char[] delimiter)
        {
            var factory = new PBKDF2CryptoProvider(saltByteSize, hashByteSize, iterations, delimiter);

            var csprng = new RNGCryptoServiceProvider();
            var arr = new byte[128];

            csprng.GetBytes(arr);

            var text = Encoding.UTF8.GetString(arr);

            Console.WriteLine("Text: {0}", text);

            var hash = factory.CreateHash(text);

            Console.WriteLine("Hash: {0}", hash);

            var valid = factory.ValidateHash(text, hash);

            Assert.IsTrue(valid);
        }
    }
}