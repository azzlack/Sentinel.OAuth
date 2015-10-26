namespace Sentinel.OAuth.Models.Providers
{
    using System;
    using System.IdentityModel.Tokens;
    using System.ServiceModel.Security.Tokens;
    using System.Text;

    using Sentinel.OAuth.Core.Constants;
    using Sentinel.OAuth.Core.Interfaces.Providers;

    public class JwtTokenProviderConfiguration
    {
        /// <summary>The digest algorithm.</summary>
        private readonly string digestAlgorithm;

        /// <summary>The signature algorithm.</summary>
        private readonly string signatureAlgorithm;

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

            // Set up algorithms
            if (cryptoProvider.HashAlgorithm == HashAlgorithm.SHA512)
            {
                this.signatureAlgorithm = "http://www.w3.org/2001/04/xmldsig-more#hmac-sha512";
                this.digestAlgorithm = "http://www.w3.org/2001/04/xmlenc#sha512";
            }
            else if (cryptoProvider.HashAlgorithm == HashAlgorithm.SHA384)
            {
                this.signatureAlgorithm = "http://www.w3.org/2001/04/xmldsig-more#hmac-sha384";
                this.digestAlgorithm = "http://www.w3.org/2001/04/xmlenc#sha384";
            }
            else
            {
                this.signatureAlgorithm = "http://www.w3.org/2001/04/xmldsig-more#hmac-sha256";
                this.digestAlgorithm = "http://www.w3.org/2001/04/xmlenc#sha256";
            }
            
            this.CryptoProvider = cryptoProvider;
            this.Issuer = issuerUri;
            this.SigningCredentials =
                new SigningCredentials(
                    new InMemorySymmetricSecurityKey(Encoding.UTF8.GetBytes(symmetricKey)),
                    this.signatureAlgorithm,
                    this.digestAlgorithm);
            this.SigningKey = new BinarySecretSecurityToken(Encoding.UTF8.GetBytes(symmetricKey));
        }

        /// <summary>Gets the crypto provider.</summary>
        /// <value>The crypto provider.</value>
        public ICryptoProvider CryptoProvider { get; }

        /// <summary>Gets the issuer.</summary>
        /// <value>The issuer.</value>
        public Uri Issuer { get; }

        /// <summary>Gets the signing credentials.</summary>
        /// <value>The signing credentials.</value>
        public SigningCredentials SigningCredentials { get; }

        /// <summary>Gets the signing key.</summary>
        /// <value>The signing key.</value>
        public SecurityToken SigningKey { get; }
    }
}