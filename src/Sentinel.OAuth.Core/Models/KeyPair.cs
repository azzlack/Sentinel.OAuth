namespace Sentinel.OAuth.Core.Models
{
    public class KeyPair
    {
        /// <summary>Initializes a new instance of the <see cref="KeyPair" /> class.</summary>
        /// <param name="privateKey">The private key.</param>
        /// <param name="publicKey">The public key.</param>
        public KeyPair(string privateKey, string publicKey)
        {
            this.PrivateKey = privateKey;
            this.PublicKey = publicKey;
        }

        /// <summary>Gets the private key.</summary>
        /// <value>The private key.</value>
        public string PrivateKey { get; }

        /// <summary>Gets the public key.</summary>
        /// <value>The public key.</value>
        public string PublicKey { get; }
    }
}