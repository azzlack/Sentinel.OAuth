namespace Sentinel.OAuth.Core.Interfaces.Managers
{
    using Sentinel.OAuth.Core.Interfaces.Identity;
    using System.Collections.Generic;
    using System.Threading.Tasks;

    using Sentinel.OAuth.Core.Interfaces.Models;
    using Sentinel.OAuth.Core.Models;

    public interface IClientManager
    {
        /// <summary>Creates a client.</summary>
        /// <param name="clientId">The client id.</param>
        /// <param name="name">The name.</param>
        /// <param name="redirectUri">The redirect URI.</param>
        /// <returns>The new client.</returns>
        Task<CreateClientResult> CreateClient(string clientId, string name, string redirectUri);

        /// <summary>
        /// Authenticates the client. Used when authenticating with the authorization_code grant type.
        /// </summary>
        /// <param name="clientId">The client id.</param>
        /// <param name="redirectUri">The redirect URI.</param>
        /// <returns>The client principal.</returns>
        Task<ISentinelPrincipal> AuthenticateClientAsync(string clientId, string redirectUri);

        /// <summary>
        /// Authenticates the client. Used when authenticating with the client_credentials grant type.
        /// </summary>
        /// <param name="clientId">The client id.</param>
        /// <param name="scope">The redirect URI.</param>
        /// <returns>The client principal.</returns>
        Task<ISentinelPrincipal> AuthenticateClientAsync(string clientId, IEnumerable<string> scope);

        /// <summary>Authenticate the client using an API key.</summary>
        /// <param name="digest">The digest.</param>
        /// <returns>The client principal.</returns>
        Task<ISentinelPrincipal> AuthenticateClientCredentialsAsync(BasicAuthenticationDigest digest);

        /// <summary>
        /// Authenticates the client credentials using client id and secret.
        /// </summary>
        /// <param name="clientId">The client id.</param>
        /// <param name="clientSecret">The client secret.</param>
        /// <returns>The client principal.</returns>
        Task<ISentinelPrincipal> AuthenticateClientCredentialsAsync(string clientId, string clientSecret);

        /// <summary>Authenticate client using signature.</summary>
        /// <param name="digest">The digest.</param>
        /// <returns>The client principal.</returns>
        Task<ISentinelPrincipal> AuthenticateClientWithSignatureAsync(SignatureAuthenticationDigest digest);
    }
}