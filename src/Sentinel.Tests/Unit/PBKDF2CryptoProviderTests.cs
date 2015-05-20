namespace Sentinel.Tests.Unit
{
    using System;
    using System.Collections.Generic;
    using System.Security.Claims;
    using System.Security.Cryptography;
    using System.Text;

    using Newtonsoft.Json;

    using NUnit.Framework;

    using Sentinel.OAuth.Core.Constants.Identity;
    using Sentinel.OAuth.Core.Interfaces.Providers;
    using Sentinel.OAuth.Implementation;
    using Sentinel.OAuth.Models.Identity;

    [TestFixture]
    [Category("Unit")]
    public class PBKDF2CryptoProviderTests
    {
        private ICryptoProvider provider;

        [SetUp]
        public void SetUp()
        {
            this.provider = new PBKDF2CryptoProvider();
        }

        [TestCase("aabbccddee")]
        public void Create_WhenGivenValidString_ReturnsHash(string text)
        {
            var hash = this.provider.CreateHash(text);

            Console.WriteLine("Hash: {0}", hash);

            Assert.IsNotNullOrEmpty(hash);
            Assert.AreEqual(3, hash.Split(':').Length);
            Assert.AreEqual("10000", hash.Split(':')[0]);
        }

        [Test]
        public void Create_WhenGeneratingString_ReturnsValidHash()
        {
            string text;
            var hash = this.provider.CreateHash(out text, 8);

            Console.WriteLine("Hash: {0}", hash);

            Assert.IsNotNullOrEmpty(hash);
            Assert.AreEqual(3, hash.Split(':').Length);
            Assert.AreEqual("10000", hash.Split(':')[0]);

            var valid = this.provider.ValidateHash(text, hash);

            Assert.IsTrue(valid);
        }

        [TestCase(8)]
        [TestCase(48)]
        [TestCase(64)]
        [TestCase(128)]
        public void Create_WhenGeneratingStringWithSpecificLength_ReturnsValidHash(int size)
        {
            string text;
            var hash = this.provider.CreateHash(out text, size);

            Console.WriteLine("Hash: {0}", hash);

            var textSize = Encoding.UTF8.GetBytes(text);

            Console.WriteLine("Text: {0}", text);
            Console.WriteLine("Text Size: {0} bits", textSize.Length * 8);

            Assert.AreEqual(size, textSize.Length * 8);

            Assert.IsNotNullOrEmpty(hash);
            Assert.AreEqual(3, hash.Split(':').Length);
            Assert.AreEqual("10000", hash.Split(':')[0]);

            var valid = this.provider.ValidateHash(text, hash);

            Assert.IsTrue(valid);
        }

        [TestCase(64, 64, 25000, new[] { ':' }, "aabbccddee")]
        [TestCase(48, 48, 25000, new[] { ':' }, "123")]
        [TestCase(64, 64, 25000, new[] { '|' }, "aabbccddee")]
        [TestCase(128, 128, 10000, new[] { ':' }, "aabbccddee")]
        public void Create_WhenGivenValidString_ReturnsHash(int saltByteSize, int hashByteSize, int iterations, char[] delimiter, string text)
        {
            var p = new PBKDF2CryptoProvider(saltByteSize, hashByteSize, iterations, delimiter);

            var hash = p.CreateHash(text);

            Console.WriteLine("Hash: {0}", hash);

            Assert.IsNotNullOrEmpty(hash);
            Assert.AreEqual(3, hash.Split(delimiter).Length);
            Assert.AreEqual(iterations.ToString(), hash.Split(delimiter)[0]);
        }

        [TestCase("aabbccddee", "10000:WDkTBrCC3uuglikSwDwjkuSNrZ6b3IYs:c81j3L+oWFzzZ1kBt6BCbRhL48dNdBL6")]
        [TestCase("aabbccddee", "10000:E+nmwGCEObvreQhlrV4clrekiUYu877i:szblNYoQohlabb31BDMdt2KFJCRtUtp8")]
        public void Validate_WhenGivenValidCorrectTextAndHashCombination_ReturnsTrue(string text, string correctHash)
        {
            var valid = this.provider.ValidateHash(text, correctHash);

            Assert.IsTrue(valid);
        }

        [TestCase(64, 64, 25000, new[] { ':' }, "aabbccddee", "25000:tUzZvrTT9NzSzUbCitZe25d1Vm71wTQjA526y1rHbq8gd/5Roq9rxNURu93A5JFOrRTvgT6urfkrLtBkW039MQ==:cFj9EgmL0p+8CWWYmnrWOsQdfWn5jCyIMHCNMmAlryvtMLUpGtWBuuERbIo4xI+4i91jZabf/CRr7Ipdb9mv0w==")]
        [TestCase(64, 64, 25000, new[] { '|' }, "aabbccddee", "25000|lErTN/RUNSvCRDQPBmQ4/Y0FL40hI7aIku47BHYeuQt0qINTeCJJ86gRE6hKHiT0UQIuXiOrsfDowqNE6tZToQ==|nbDni54XduFJJdmGiPxvr5sLn7USBN66Gad8lrLr2J+mtZT2TR1UBu9O41iXfsI0GQXx2HL0httGL6nDiL1Ncg==")]
        public void Validate_WhenGivenValidCorrectTextAndHashCombination_ReturnsTrue(int saltByteSize, int hashByteSize, int iterations, char[] delimiter, string text, string correctHash)
        {
            var p = new PBKDF2CryptoProvider(saltByteSize, hashByteSize, iterations, delimiter);

            var valid = p.ValidateHash(text, correctHash);

            Assert.IsTrue(valid);
        }

        [TestCase("aabbccddee", "9000:WDkTBrCC3uuglikSwDwjkuSNrZ6b3IYs:c81j3L+oWFzzZ1kBt6BCbRhL48dNdBL6")]
        [TestCase("aabbccddee", "10000:E+nmwGCEObvreQhlrV4clrfkiUYu877i:szblNYoQohlabb31BDMdt2KFJCRtUtp8")]
        public void Validate_WhenGivenIncorrectTextAndHashCombination_ReturnsFalse(string text, string correctHash)
        {
            var valid = this.provider.ValidateHash(text, correctHash);

            Assert.IsFalse(valid);
        }


        [TestCase(64, 64, 25000, new[] { ':' }, "aabbccddee", "9000:WDkTBrCC3uuglikSwDwjkuSNrZ6b3IYs:c81j3L+oWFzzZ1kBt6BCbRhL48dNdBL6")]
        [TestCase(64, 64, 25000, new[] { '|' }, "aabbccddee", "10000|E+nmwGCEObwreQhlrV4clrekiUYu877i|szblNYoQohlabb31BDMdt2KFJCRtUtp8")]
        public void Validate_WhenGivenIncorrectTextAndHashCombination_ReturnsFalse(int saltByteSize, int hashByteSize, int iterations, char[] delimiter, string text, string correctHash)
        {
            var p = new PBKDF2CryptoProvider(saltByteSize, hashByteSize, iterations, delimiter);

            var valid = p.ValidateHash(text, correctHash);

            Assert.IsFalse(valid);
        }

        [TestCase(64, 64, 25000, new[] { '|' })]
        [TestCase(24, 24, 10000, new[] { ':' })]
        public void Validate_WhenGivenAutoGeneratedString_ReturnsValid(int saltByteSize, int hashByteSize, int iterations, char[] delimiter)
        {
            var p = new PBKDF2CryptoProvider(saltByteSize, hashByteSize, iterations, delimiter);

            var csprng = new RNGCryptoServiceProvider();
            var arr = new byte[128];

            csprng.GetBytes(arr);

            var text = Encoding.UTF8.GetString(arr);

            Console.WriteLine("Text: {0}", text);

            var hash = p.CreateHash(text);

            Console.WriteLine("Hash: {0}", hash);

            var valid = p.ValidateHash(text, hash);

            Assert.IsTrue(valid);
        }

        [TestCase("Lorem ipsum", "myspecialkey")]
        [TestCase("b dnsnfgrsnfgnfghnfgnfg", "some otherky")]
        public void Encrypt_WhenGivenString_ReturnsEncryptedString(string text, string key)
        {
            var r = this.provider.Encrypt(text, key);

            Console.WriteLine("Original: {0}", text);
            Console.WriteLine("Encrypted: {0}", r);

            Assert.IsNotNullOrEmpty(r);
        }

        [TestCase("v s bvzølnbdskøcmbøsdmvdøsbvjkdsb mvbdsvndjkls")]
        [TestCase("myspecialkey")]
        public void Decrypt_WhenGivenEncryptedString_ReturnsDecryptedString(string key)
        {
            var c1 = new SentinelPrincipal(new SentinelIdentity(AuthenticationType.OAuth, new SentinelClaim(ClaimTypes.Name, "azzlack")));
            var s = JsonConvert.SerializeObject(c1);

            var e = this.provider.Encrypt(s, key);

            Console.WriteLine("Original: {0}", s);
            Console.WriteLine();
            Console.WriteLine("Encrypted: {0}", e);
            Console.WriteLine();

            var d = this.provider.Decrypt(e, key);

            Console.WriteLine("Decrypted: {0}", d);

            var c2 = JsonConvert.DeserializeObject<SentinelPrincipal>(d);

            Assert.AreEqual(c1.Identity.Name, c2.Identity.Name);
        }
    }
}