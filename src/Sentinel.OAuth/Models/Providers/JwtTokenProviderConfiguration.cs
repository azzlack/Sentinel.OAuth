namespace Sentinel.OAuth.Models.Providers
{
    using System.IdentityModel.Tokens;
    using System.ServiceModel.Security.Tokens;
    using System.Text;

    public class JwtTokenProviderConfiguration
    {
        /// <summary>Initializes a new instance of the Sentinel.OAuth.Models.Providers.JwtTokenProviderConfiguration class.</summary>
        /// <param name="issuerName">Name of the issuer.</param>
        /// <param name="symmetricKey">The symmetric key.</param>
        public JwtTokenProviderConfiguration(string issuerName, string symmetricKey)
        {
            // TODO: Add support for using certificate instead of symmetric key

            this.Issuer = issuerName;
            this.SigningCredentials =
                new SigningCredentials(
                    new InMemorySymmetricSecurityKey(Encoding.UTF8.GetBytes(symmetricKey)),
                    "http://www.w3.org/2001/04/xmldsig-more#hmac-sha256",
                    "http://www.w3.org/2001/04/xmlenc#sha256");
            this.SigningKey = new BinarySecretSecurityToken(Encoding.UTF8.GetBytes(symmetricKey));
        }

        /// <summary>Gets the issuer.</summary>
        /// <value>The issuer.</value>
        public string Issuer { get; }

        /// <summary>Gets the signing credentials.</summary>
        /// <value>The signing credentials.</value>
        public SigningCredentials SigningCredentials { get; }

        /// <summary>Gets the signing key.</summary>
        /// <value>The signing key.</value>
        public SecurityToken SigningKey { get; }
    }
}