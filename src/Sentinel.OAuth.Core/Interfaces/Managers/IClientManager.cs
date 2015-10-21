namespace Sentinel.OAuth.Core.Interfaces.Managers
{
    using Sentinel.OAuth.Core.Interfaces.Identity;
    using System.Collections.Generic;
    using System.Threading.Tasks;

    public interface IClientManager
    {
        /// <summary>
        ///     Authenticates the client.
        ///     Used when authenticating with the authorization_code grant type.
        /// </summary>
        /// <param name="clientId">The client id.</param>
        /// <param name="redirectUri">The redirect URI.</param>
        /// <returns>The client principal.</returns>
        Task<ISentinelPrincipal> AuthenticateClientAsync(string clientId, string redirectUri);

        /// <summary>
        ///     Authenticates the client.
        ///     Used when authenticating with the client_credentials grant type.
        /// </summary>
        /// <param name="clientId">The client id.</param>
        /// <param name="scope">The redirect URI.</param>
        /// <returns>The client principal.</returns>
        Task<ISentinelPrincipal> AuthenticateClientAsync(string clientId, IEnumerable<string> scope);

        /// <summary>
        /// Authenticates the client credentials using client id and secret.
        /// </summary>
        /// <param name="clientId">The client id.</param>
        /// <param name="clientSecret">The client secret.</param>
        /// <returns>The client principal.</returns>
        Task<ISentinelPrincipal> AuthenticateClientCredentialsAsync(string clientId, string clientSecret);
    }
}