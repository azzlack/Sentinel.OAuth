namespace Sentinel.OAuth.Implementation
{
    using System;
    using System.IO;
    using System.Security.Cryptography;
    using System.Text;

    using Sentinel.OAuth.Core.Interfaces.Providers;

    /// <summary>A <c>PBKDF2</c> crypto provider for creating and validating hashes.</summary>
    public class PBKDF2CryptoProvider : ICryptoProvider
    {
        /// <summary>
        /// The salt size.
        /// </summary>
        private readonly int saltByteSize;

        /// <summary>
        /// The hash size.
        /// </summary>
        private readonly int hashByteSize;

        /// <summary>
        /// The number of iterations used by the PBKDF2 algorithm.
        /// </summary>
        private readonly int iterations;

        /// <summary>
        /// The hash components delimiter.
        /// </summary>
        private readonly char[] delimiter;

        /// <summary>
        /// The random number generator.
        /// </summary>
        private readonly RandomNumberGenerator rng;

        /// <summary>
        /// Initializes a new instance of the <see cref="PBKDF2CryptoProvider" /> class.
        /// </summary>
        /// <param name="saltByteSize">The salt size. Defaults to 24.</param>
        /// <param name="hashByteSize">The hash size. Defaults to 24.</param>
        /// <param name="iterations">The number of iterations used by the algorithm. Defaults to 10000.</param>
        /// <param name="delimiter">The hash components delimiter. Defaults to ':'.</param>
        public PBKDF2CryptoProvider(int saltByteSize = 128, int hashByteSize = 128, int iterations = 10000, char[] delimiter = null)
        {
            this.saltByteSize = saltByteSize;
            this.hashByteSize = hashByteSize;
            this.iterations = iterations;
            this.delimiter = delimiter ?? new[] { ':' };

            this.rng = new RNGCryptoServiceProvider();
        }

        /// <summary>
        /// Creates a hash of a random text.
        /// </summary>
        /// <param name="text">The text that was hashed.</param>
        /// <param name="textLength">The random text length in bits.</param>
        /// <returns>The hash of the text.</returns>
        public string CreateHash(out string text, int textLength)
        {
            text = this.GenerateText(textLength);

            return this.CreateHash(text);
        }

        /// <summary>
        /// Creates a hash of the specified text.
        /// </summary>
        /// <param name="text">The text to hash.</param>
        /// <returns>The hash of the the text.</returns>
        public string CreateHash(string text)
        {
            // Generate a random salt
            var salt = this.GenerateSalt();

            // Hash the password and encode the parameters
            var hash = this.Compute(text, salt, this.iterations, this.hashByteSize);

            return string.Format("{1}{0}{2}{0}{3}", string.Join("", this.delimiter), this.iterations, Convert.ToBase64String(salt), Convert.ToBase64String(hash));
        }

        /// <summary>
        /// Validates the specified text against the specified hash.
        /// </summary>
        /// <param name="text">The text.</param>
        /// <param name="correctHash">The correct hash.</param>
        /// <returns><c>true</c> if the text can be converted into the correct hash, <c>false</c> otherwise.</returns>
        public bool ValidateHash(string text, string correctHash)
        {
            var components = correctHash.Split(this.delimiter);

            // Dont bother validating if the number of components doesnt match up
            if (components.Length != 3)
            {
                return false;
            }

            var iterations = Int32.Parse(components[0]);
            var salt = Convert.FromBase64String(components[1]);
            var hash = Convert.FromBase64String(components[2]);

            var testHash = this.Compute(text, salt, iterations, hash.Length);

            return this.SlowEquals(hash, testHash);
        }

        /// <summary>Encrypts the specified text.</summary>
        /// <param name="text">The text.</param>
        /// <param name="key">The key.</param>
        /// <returns>The encrypted text.</returns>
        public string Encrypt(string text, string key)
        {
            // Create random key generator
            var pdb = new Rfc2898DeriveBytes(key, Encoding.UTF8.GetBytes(key));

            // Encrypt the principal
            byte[] encrypted;

            using (var rijAlg = new RijndaelManaged() { Key = pdb.GetBytes(32), IV = pdb.GetBytes(16) })
            {
                var encryptor = rijAlg.CreateEncryptor(rijAlg.Key, rijAlg.IV);

                using (var msEncrypt = new MemoryStream())
                {
                    using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (var swEncrypt = new StreamWriter(csEncrypt))
                        {
                            swEncrypt.Write(text);
                        }

                        encrypted = msEncrypt.ToArray();
                    }
                }
            }

            return Convert.ToBase64String(encrypted);
        }

        /// <summary>Decrypts the principal.</summary>
        /// <param name="ticket">The encrypted principal.</param>
        /// <param name="key">The key.</param>
        /// <returns>The principal.</returns>
        public string Decrypt(string ticket, string key)
        {
            string decryptedText;

            // Create random key generator
            var pdb = new Rfc2898DeriveBytes(key, Encoding.UTF8.GetBytes(key));

            using (var rijAlg = new RijndaelManaged() { Key = pdb.GetBytes(32), IV = pdb.GetBytes(16) })
            {
                var decryptor = rijAlg.CreateDecryptor(rijAlg.Key, rijAlg.IV);

                using (var msDecrypt = new MemoryStream(Convert.FromBase64String(ticket)))
                {
                    using (var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (var srDecrypt = new StreamReader(csDecrypt))
                        {
                            decryptedText = srDecrypt.ReadToEnd();
                        }
                    }
                }
            }

            return decryptedText;
        }

        /// <summary>
        /// Generates a random text.
        /// </summary>
        /// <param name="length">The text length.</param>
        /// <returns>The random text.</returns>
        private string GenerateText(int length)
        {
            const string AllowedChars = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNOPQRSTUVWXYZ0123456789!@$?_-";

            var max = length / 8;
            var text = new byte[max];

            for (var i = 0; i < max; i++)
            {
                var index = this.GetRandomIndex(0, AllowedChars.Length);

                text[i] = Convert.ToByte(AllowedChars[index]);
            }

            return Encoding.UTF8.GetString(text);
        }

        /// <summary>
        /// Generates a random salt.
        /// </summary>
        /// <returns>The random salt.</returns>
        private byte[] GenerateSalt()
        {
            var csprng = new RNGCryptoServiceProvider();
            var salt = new byte[this.saltByteSize];

            csprng.GetBytes(salt);

            return salt;
        }

        /// <summary>
        /// Compares two byte arrays in length-constant time. This comparison
        /// method is used so that password hashes cannot be extracted from
        /// on-line systems using a timing attack and then attacked off-line.
        /// </summary>
        /// <param name="a">The first byte array.</param>
        /// <param name="b">The second byte array.</param>
        /// <returns>True if both byte arrays are equal. False otherwise.</returns>
        private bool SlowEquals(byte[] a, byte[] b)
        {
            var diff = (uint)a.Length ^ (uint)b.Length;

            for (var i = 0; i < a.Length && i < b.Length; i++)
            {
                diff |= (uint)(a[i] ^ b[i]);
            }

            return diff == 0;
        }

        /// <summary>
        /// Computes the PBKDF2-SHA1 hash of a text.
        /// </summary>
        /// <param name="text">The text to hash.</param>
        /// <param name="salt">The salt.</param>
        /// <param name="iterations">The iteration count.</param>
        /// <param name="outputBytes">The length of the hash to generate, in bytes.</param>
        /// <returns>A hash of the text.</returns>
        private byte[] Compute(string text, byte[] salt, int iterations, int outputBytes)
        {
            var pbkdf2 = new Rfc2898DeriveBytes(text, salt, iterations);

            return pbkdf2.GetBytes(outputBytes);
        }

        /// <summary>
        /// Gets a random index.
        /// </summary>
        /// <param name="minValue">The minimum value.</param>
        /// <param name="maxValue">The maximum value.</param>
        /// <returns>The index.</returns>
        private int GetRandomIndex(int minValue, int maxValue)
        {
            const long Max = (1 + (Int64)UInt32.MaxValue);

            var buffer = new byte[4];

            if (minValue > maxValue)
            {
                throw new ArgumentOutOfRangeException("minValue");
            }

            if (minValue == maxValue)
            {
                return minValue;
            }

            Int64 diff = maxValue - minValue;

            while (true)
            {
                this.rng.GetBytes(buffer);
                var rand = BitConverter.ToUInt32(buffer, 0);

                var remainder = Max % diff;

                if (rand < Max - remainder)
                {
                    return (Int32)(minValue + (rand % diff));
                }
            }
        }
    }
}