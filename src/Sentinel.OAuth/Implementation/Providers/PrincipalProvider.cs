namespace Sentinel.OAuth.Implementation.Providers
{
    using System;
    using System.Security.Claims;

    using Newtonsoft.Json;

    using Sentinel.OAuth.Core.Interfaces.Identity;
    using Sentinel.OAuth.Core.Interfaces.Providers;
    using Sentinel.OAuth.Models.Identity;

    public class PrincipalProvider : IPrincipalProvider
    {
        /// <summary>The crypto provider.</summary>
        private readonly ICryptoProvider cryptoProvider;

        /// <summary>
        /// The current principal
        /// </summary>
        private readonly Lazy<ClaimsPrincipal> current = new Lazy<ClaimsPrincipal>(() => ClaimsPrincipal.Current);

        /// <summary>
        ///     Initializes a new instance of the Sentinel.OAuth.Implementation.PrincipalProvider
        ///     class.
        /// </summary>
        /// <param name="cryptoProvider">The crypto provider.</param>
        public PrincipalProvider(ICryptoProvider cryptoProvider)
        {
            if (cryptoProvider == null)
            {
                throw new ArgumentNullException("cryptoProvider");
            }

            this.cryptoProvider = cryptoProvider;
        }

        /// <summary>
        /// Creates an anonymous claims principal.
        /// </summary>
        /// <value>An anonymous claims principal.</value>
        public ISentinelPrincipal Anonymous
        {
            get
            {
                return new SentinelPrincipal();
            }
        }

        /// <summary>
        /// Gets the current principal.
        /// </summary>
        /// <value>The current principal.</value>
        public ISentinelPrincipal Current
        {
            get
            {
                return new SentinelPrincipal(this.current.Value);
            }
        }

        /// <summary>
        /// Creates a claims principal with the specified authentication type and claims.
        /// </summary>
        /// <param name="authenticationType">Type of the authentication.</param>
        /// <param name="claims">The claims.</param>
        /// <returns>A claims principal.</returns>
        public ISentinelPrincipal Create(string authenticationType, params ISentinelClaim[] claims)
        {
            if (claims == null)
            {
                throw new ArgumentNullException("claims");
            }

            return new SentinelPrincipal(new SentinelIdentity(authenticationType, claims));
        }

        /// <summary>
        /// Encrypts the specified principal.
        /// </summary>
        /// <param name="principal">The principal.</param>
        /// <param name="key">The key.</param>
        /// <returns>The encrypted principal.</returns>
        public string Encrypt(ISentinelPrincipal principal, string key)
        {
            var s = JsonConvert.SerializeObject(principal);

            return this.cryptoProvider.Encrypt(s, key);
        }

        /// <summary>
        /// Decrypts the specified encrypted principal.
        /// </summary>
        /// <param name="ticket">The encrypted principal.</param>
        /// <param name="key">The key.</param>
        /// <returns>The principal.</returns>
        public ISentinelPrincipal Decrypt(string ticket, string key)
        {
            var s = this.cryptoProvider.Decrypt(ticket, key);

            return JsonConvert.DeserializeObject<SentinelPrincipal>(s);
        }
    }
}