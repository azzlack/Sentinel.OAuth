namespace Sentinel.OAuth.Implementation.Providers
{
    using System;
    using System.Collections.Generic;
    using System.Diagnostics;
    using System.Security;
    using System.Security.Cryptography;
    using System.Text;

    using Sentinel.OAuth.Core.Interfaces.Providers;

    public class AsymmetricCryptoProvider : IAsymmetricCryptoProvider
    {
        /// <summary>Size of the key.</summary>
        private readonly int keySize;

        /// <summary>The hash algorithm.</summary>
        private readonly HashAlgorithm hashAlgorithm;

        /// <summary>Initializes a new instance of the <see cref="AsymmetricCryptoProvider" /> class.</summary>
        /// <param name="keySize">Size of the key.</param>
        /// <param name="hashAlgorithm">The hash algorithm.</param>
        public AsymmetricCryptoProvider(int keySize = 512, Core.Constants.HashAlgorithm hashAlgorithm = Core.Constants.HashAlgorithm.SHA256)
        {
            this.keySize = keySize;

            switch (hashAlgorithm)
            {
                case Sentinel.OAuth.Core.Constants.HashAlgorithm.SHA256:
                    this.hashAlgorithm = new SHA256CryptoServiceProvider();
                    break;
                case Sentinel.OAuth.Core.Constants.HashAlgorithm.SHA384:
                    this.hashAlgorithm = new SHA384CryptoServiceProvider();
                    break;
                case Sentinel.OAuth.Core.Constants.HashAlgorithm.SHA512:
                    this.hashAlgorithm = new SHA512CryptoServiceProvider();
                    break;
                default:
                    throw new ArgumentException("Invalid hash algorithm. Only SHA256, SHA384, SHA512 is supported", nameof(hashAlgorithm));
            }
        }

        /// <summary>Creates a private/public key pair.</summary>
        /// <returns>The private/public key pair, base-64 encoded.</returns>
        public KeyValuePair<string, string> GenerateKeys()
        {
            using (var rsa = new RSACryptoServiceProvider(this.keySize))
            {
                rsa.PersistKeyInCsp = false;
                var privateKey = rsa.ToXmlString(true);
                var publicKey = rsa.ToXmlString(false);

                return new KeyValuePair<string, string>(Convert.ToBase64String(Encoding.UTF8.GetBytes(privateKey)), Convert.ToBase64String(Encoding.UTF8.GetBytes(publicKey)));
            }
        }

        /// <summary>Signs the data using the specified key.</summary>
        /// <param name="data">The data.</param>
        /// <param name="privateKey">The private key, base-64 encoded.</param>
        /// <returns>The signature, base-64 encoded.</returns>
        public string Sign(string data, string privateKey)
        {
            using (var rsa = new RSACryptoServiceProvider(this.keySize))
            {
                rsa.PersistKeyInCsp = false;

                try
                {
                    rsa.FromXmlString(Encoding.UTF8.GetString(Convert.FromBase64String(privateKey)));
                }
                catch (CryptographicException ex)
                {
                    throw new ArgumentException("The private key is invalid", nameof(privateKey), ex);
                }
                catch (XmlSyntaxException ex)
                {
                    throw new ArgumentException("The private key is invalid", nameof(privateKey), ex);
                }

                var signature = rsa.SignData(Encoding.UTF8.GetBytes(data), this.hashAlgorithm);

                return Convert.ToBase64String(signature);
            }
        }

        /// <summary>Validates the signature using the specified key.</summary>
        /// <param name="data">The data.</param>
        /// <param name="signature">The signature, base-64 encoded.</param>
        /// <param name="publicKey">The public key, base-64 encoded.</param>
        /// <returns><c>True</c> if successfull, <c>false</c> otherwise.</returns>
        public bool ValidateSignature(string data, string signature, string publicKey)
        {
            using (var rsa = new RSACryptoServiceProvider(this.keySize))
            {
                rsa.PersistKeyInCsp = false;

                try
                {
                    rsa.FromXmlString(Encoding.UTF8.GetString(Convert.FromBase64String(publicKey)));
                }
                catch (FormatException)
                {
                    Debug.WriteLine("The public key is not a valid Base-64 string");

                    return false;
                }
                catch (CryptographicException ex)
                {
                    throw new ArgumentException("The public key is invalid", nameof(publicKey), ex);
                }
                catch (XmlSyntaxException ex)
                {
                    throw new ArgumentException("The public key is invalid", nameof(publicKey), ex);
                }

                return rsa.VerifyData(Encoding.UTF8.GetBytes(data), this.hashAlgorithm, Convert.FromBase64String(signature));
            }
        }
    }
}