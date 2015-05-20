namespace Sentinel.OAuth.Implementation
{
    using System;
    using System.IO;
    using System.Linq;
    using System.Security.Cryptography;
    using System.Text;

    using Common.Logging;

    using Sentinel.OAuth.Core.Interfaces.Providers;

    /// <summary>A <c>SHA-2</c> crypto provider for creating and validating hashes.</summary>
    public class SHA2CryptoProvider : ICryptoProvider
    {
        /// <summary>The salt size.</summary>
        private readonly int saltByteSize;

        /// <summary>The random number generator.</summary>
        private readonly RandomNumberGenerator rng;

        /// <summary>The log.</summary>
        private readonly ILog log;

        /// <summary>
        /// Initializes a new instance of the <see cref="SHA2CryptoProvider" /> class.
        /// </summary>
        /// <param name="saltByteSize">The salt size. Defaults to 64.</param>
        public SHA2CryptoProvider(int saltByteSize = 64)
        {
            this.saltByteSize = saltByteSize;

            this.rng = new RNGCryptoServiceProvider();
            this.log = LogManager.GetLogger("Sentinel.OAuth.SHA2CryptoProvider");
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
            this.log.Debug("Creating hash");

            // Generate a random salt
            var salt = this.GenerateSalt();

            // Hash the password and encode the parameters
            var hash = this.Compute(Encoding.UTF8.GetBytes(text), salt);

            var result = Convert.ToBase64String(hash);

            this.log.Debug("Successfully created hash");

            return result;
        }

        /// <summary>
        /// Validates the specified text against the specified hash.
        /// </summary>
        /// <param name="text">The text.</param>
        /// <param name="correctHash">The correct hash.</param>
        /// <returns><c>true</c> if the text can be converted into the correct hash, <c>false</c> otherwise.</returns>
        public bool ValidateHash(string text, string correctHash)
        {
            this.log.Debug("Validating hash");

            byte[] saltedHash;

            try
            {
                saltedHash = Convert.FromBase64String(correctHash);
            }
            catch (FormatException ex)
            {
                this.log.Error(string.Format("The hash '{0}' is not a valid base64 encoded string", correctHash), ex);
                return false;
            }

            // Get salt from the end of the hash
            var offset = saltedHash.Length - this.saltByteSize;
            var saltBytes = new byte[this.saltByteSize];
            Buffer.BlockCopy(saltedHash, offset, saltBytes, 0, this.saltByteSize);

            // Compute new hash from the supplied text and the extracted salt
            var newHash = this.Compute(Encoding.UTF8.GetBytes(text), saltBytes);

            // If the hashes match, the text is valid
            var result = saltedHash.SequenceEqual(newHash);

            if (result)
            {
                this.log.Debug("The hash was valid");
            }
            else
            {
                this.log.Warn("The hash was invalid");
            }

            return result;
        }

        /// <summary>Encrypts the specified text.</summary>
        /// <param name="text">The text.</param>
        /// <param name="key">The key.</param>
        /// <returns>The encrypted text.</returns>
        public string Encrypt(string text, string key)
        {
            this.log.DebugFormat("Encrypting '{0}'", text);

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

            this.log.Debug("Encryption complete");

            return Convert.ToBase64String(encrypted);
        }

        /// <summary>Decrypts the principal.</summary>
        /// <param name="ticket">The encrypted principal.</param>
        /// <param name="key">The key.</param>
        /// <returns>The principal.</returns>
        public string Decrypt(string ticket, string key)
        {
            this.log.DebugFormat("Decrypting '{0}'", ticket);

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

            this.log.Debug("Decryption complete");

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
        /// Computes the PBKDF2-SHA1 hash of a text.
        /// </summary>
        /// <param name="text">The text to hash.</param>
        /// <param name="salt">The salt.</param>
        /// <returns>A hash of the text.</returns>
        private byte[] Compute(byte[] text, byte[] salt)
        {
            using (var sha = new SHA512CryptoServiceProvider())
            {
                // Prepend salt to text
                var saltedText = new byte[salt.Length + text.Length];
                Buffer.BlockCopy(salt, 0, saltedText, 0, salt.Length);
                Buffer.BlockCopy(text, 0, saltedText, salt.Length, text.Length);

                // Create hash
                var hash = sha.ComputeHash(saltedText);

                // Append salt to hash
                var saltedHash = new byte[hash.Length + salt.Length];
                Buffer.BlockCopy(hash, 0, saltedHash, 0, hash.Length);
                Buffer.BlockCopy(salt, 0, saltedHash, hash.Length, salt.Length);

                return saltedHash;
            }
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