namespace Sentinel.OAuth.Core.Managers
{
    using System.Collections.Generic;
    using System.Threading.Tasks;

    using Sentinel.OAuth.Core.Interfaces.Identity;
    using Sentinel.OAuth.Core.Interfaces.Managers;
    using Sentinel.OAuth.Core.Interfaces.Providers;

    /// <summary>A base client manager.</summary>
    public abstract class BaseClientManager : IClientManager
    {
        /// <summary>
        /// Initializes a new instance of the Sentinel.OAuth.Core.Models.Managers.BaseClientManager
        /// class.
        /// </summary>
        /// <param name="cryptoProvider">The crypto provider.</param>
        protected BaseClientManager(ICryptoProvider cryptoProvider)
        {
            this.CryptoProvider = cryptoProvider;
        }

        /// <summary>Gets the crypto provider.</summary>
        /// <value>The crypto provider.</value>
        protected ICryptoProvider CryptoProvider { get; private set; }

        /// <summary>
        /// Authenticates the client. Used when authenticating with the authorization_code grant type.
        /// </summary>
        /// <param name="clientId">The client id.</param>
        /// <param name="redirectUri">The redirect URI.</param>
        /// <returns>The client principal.</returns>
        public abstract Task<ISentinelPrincipal> AuthenticateClientAsync(string clientId, string redirectUri);

        /// <summary>
        /// Authenticates the client. Used when authenticating with the client_credentials grant type.
        /// </summary>
        /// <param name="clientId">The client id.</param>
        /// <param name="scope">The redirect URI.</param>
        /// <returns>The client principal.</returns>
        public abstract Task<ISentinelPrincipal> AuthenticateClientAsync(string clientId, IEnumerable<string> scope);

        /// <summary>Authenticates the client credentials using client id and secret.</summary>
        /// <param name="clientId">The client id.</param>
        /// <param name="clientSecret">The client secret.</param>
        /// <returns>The client principal.</returns>
        public abstract Task<ISentinelPrincipal> AuthenticateClientCredentialsAsync(string clientId, string clientSecret);
    }
}