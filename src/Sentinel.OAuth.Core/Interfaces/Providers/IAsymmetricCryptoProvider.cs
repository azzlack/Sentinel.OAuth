namespace Sentinel.OAuth.Core.Interfaces.Providers
{
    using System.Collections.Generic;

    using Sentinel.OAuth.Core.Models;

    public interface IAsymmetricCryptoProvider
    {
        /// <summary>Creates a private/public key pair.</summary>
        /// <returns>The private/public key pair, base-64 encoded.</returns>
        KeyPair GenerateKeys();

        /// <summary>Signs the data using the specified key.</summary>
        /// <param name="data">The data.</param>
        /// <param name="privateKey">The private key, base-64 encoded.</param>
        /// <returns>The signature, base-64 encoded.</returns>
        string Sign(string data, string privateKey);

        /// <summary>Validates the signature using the specified key.</summary>
        /// <param name="data">The data.</param>
        /// <param name="signature">The signature, base-64 encoded.</param>
        /// <param name="publicKey">The public key, base-64 encoded.</param>
        /// <returns><c>True</c> if successfull, <c>false</c> otherwise.</returns>
        bool ValidateSignature(string data, string signature, string publicKey);
    }
}