namespace Sentinel.OAuth.Core.Interfaces.Providers
{
    /// <summary>Interface for a provider for creating and validating hashes.</summary>
    public interface ICryptoProvider
    {
        /// <summary>
        /// Creates a hash of a random text.
        /// </summary>
        /// <param name="text">The text that was hashed.</param>
        /// <param name="length">The random text length in bits.</param>
        /// <returns>The hash of the text.</returns>
        string CreateHash(out string text, int length = 8);

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
    }
}