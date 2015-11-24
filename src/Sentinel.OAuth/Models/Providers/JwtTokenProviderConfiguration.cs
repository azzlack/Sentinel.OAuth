namespace Sentinel.OAuth.Models.Providers
{
    using Sentinel.OAuth.Core.Constants;
    using Sentinel.OAuth.Core.Interfaces.Providers;
    using System;
    using System.IdentityModel.Tokens;
    using System.ServiceModel.Security.Tokens;

    public class JwtTokenProviderConfiguration
    {
        /// <summary>
        /// Initializes a new instance of the
        /// Sentinel.OAuth.Models.Providers.JwtTokenProviderConfiguration class.
        /// </summary>
        /// <param name="cryptoProvider">The crypto provider.</param>
        /// <param name="issuerUri">The issuer URI.</param>
        /// <param name="symmetricKey">The symmetric key.</param>
        public JwtTokenProviderConfiguration(ICryptoProvider cryptoProvider, Uri issuerUri, string symmetricKey)
        {
            // TODO: Add support for using certificate instead of symmetric key

            this.CryptoProvider = cryptoProvider;
            this.Issuer = issuerUri;

            this.CreateSymmetricKeySigningCredentials(Convert.FromBase64String(symmetricKey));
        }

        /// <summary>Gets the crypto provider.</summary>
        /// <value>The crypto provider.</value>
        public ICryptoProvider CryptoProvider { get; }

        /// <summary>Gets the issuer.</summary>
        /// <value>The issuer.</value>
        public Uri Issuer { get; }

        /// <summary>Gets the signing credentials.</summary>
        /// <value>The signing credentials.</value>
        public SigningCredentials SigningCredentials { get; private set; }

        /// <summary>Gets the signing key.</summary>
        /// <value>The signing key.</value>
        public SecurityToken SigningKey { get; private set; }

        /// <summary>Creates symmetric key signing credentials.</summary>
        /// <param name="key">The key.</param>
        private void CreateSymmetricKeySigningCredentials(byte[] key)
        {
            string signatureAlgorithm;
            string digestAlgorithm;

            if (this.CryptoProvider.HashAlgorithm == HashAlgorithm.SHA512 && key.Length == 64)
            {
                signatureAlgorithm = "http://www.w3.org/2001/04/xmldsig-more#hmac-sha512";
                digestAlgorithm = "http://www.w3.org/2001/04/xmlenc#sha512";
            }
            else if (this.CryptoProvider.HashAlgorithm == HashAlgorithm.SHA384 && key.Length == 48)
            {
                signatureAlgorithm = "http://www.w3.org/2001/04/xmldsig-more#hmac-sha384";
                digestAlgorithm = "http://www.w3.org/2001/04/xmlenc#sha384";
            }
            else if (this.CryptoProvider.HashAlgorithm == HashAlgorithm.SHA256 && key.Length == 32)
            {
                signatureAlgorithm = "http://www.w3.org/2001/04/xmldsig-more#hmac-sha256";
                digestAlgorithm = "http://www.w3.org/2001/04/xmlenc#sha256";
            }
            else
            {
                throw new ArgumentException($"Unsupported key length. When using {this.CryptoProvider.HashAlgorithm}, the key must be {(int)this.CryptoProvider.HashAlgorithm / 8} bytes, the specified key is {key.Length} bytes.", nameof(key));
            }

            this.SigningCredentials =
                new SigningCredentials(
                    new InMemorySymmetricSecurityKey(key),
                    signatureAlgorithm,
                    digestAlgorithm);
            this.SigningKey = new BinarySecretSecurityToken(key);
        }
    }
}