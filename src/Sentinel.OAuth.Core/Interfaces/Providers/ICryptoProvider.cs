namespace Sentinel.OAuth.Core.Interfaces.Providers
{
    using System.Security.Claims;

    /// <summary>Interface for a provider for creating and validating hashes.</summary>
    public interface ICryptoProvider
    {
        /// <summary>
        /// Creates a hash of a random text.
        /// </summary>
        /// <param name="text">The text that was hashed.</param>
        /// <param name="length">The random text length in bits. A value of minimum 256 is recommended.</param>
        /// <returns>The hash of the text.</returns>
        string CreateHash(out string text, int length);

        /// <summary>
        /// Creates a hash of the specified text.
        /// </summary>
        /// <param name="text">The text to hash.</param>
        /// <returns>The hash of the text.</returns>
        string CreateHash(string text);

        /// <summary>
        /// Validates the specified text against the specified hash.
        /// </summary>
        /// <param name="text">The text.</param>
        /// <param name="correctHash">The correct hash.</param>
        /// <returns><c>true</c> if the text can be converted into the correct hash, <c>false</c> otherwise.</returns>
        bool ValidateHash(string text, string correctHash);

        /// <summary>Encrypts the specified text.</summary>
        /// <param name="text">The text.</param>
        /// <param name="key">The key.</param>
        /// <returns>The encrypted text.</returns>
        string Encrypt(string text, string key);

        /// <summary>Decrypts the specified text.</summary>
        /// <param name="ticket">The encrypted text.</param>
        /// <param name="key">The key.</param>
        /// <returns>The unencrypted text.</returns>
        string Decrypt(string ticket, string key);
    }
}