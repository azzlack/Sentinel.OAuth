namespace Sentinel.OAuth.Implementation.Managers
{
    using System;

    using Sentinel.OAuth.Core.Constants.Identity;
    using Sentinel.OAuth.Core.Interfaces.Identity;
    using Sentinel.OAuth.Core.Interfaces.Providers;
    using Sentinel.OAuth.Core.Interfaces.Repositories;
    using Sentinel.OAuth.Core.Managers;
    using Sentinel.OAuth.Models.Identity;
    using System.Collections.Generic;
    using System.Security.Claims;
    using System.Threading.Tasks;

    public class ClientManager : BaseClientManager
    {
        /// <summary>Initializes a new instance of the <see cref="ClientManager" /> class.</summary>
        /// <param name="cryptoProvider">The crypto provider.</param>
        /// <param name="clientRepository">The client repository.</param>
        public ClientManager(ICryptoProvider cryptoProvider, IClientRepository clientRepository)
            : base(cryptoProvider, clientRepository)
        {
        }

        /// <summary>
        /// Authenticates the client. Used when authenticating with the authorization_code grant type.
        /// </summary>
        /// <param name="clientId">The client id.</param>
        /// <param name="redirectUri">The redirect URI.</param>
        /// <returns>The client principal.</returns>
        public override async Task<ISentinelPrincipal> AuthenticateClientAsync(string clientId, string redirectUri)
        {
            var client = await this.ClientRepository.GetClient(clientId);

            if (client != null && client.Enabled && client.RedirectUri == redirectUri)
            {
                var principal =
                    new SentinelPrincipal(
                        new SentinelIdentity(
                            AuthenticationType.OAuth,
                            new SentinelClaim(JwtClaimType.Name, clientId),
                            new SentinelClaim(ClaimType.RedirectUri, client.RedirectUri),
                            new SentinelClaim(ClaimTypes.AuthenticationMethod, AuthenticationMethod.ClientId)));

                if (principal.Identity.IsAuthenticated)
                {
                    client.LastUsed = DateTimeOffset.UtcNow;
                    await this.ClientRepository.Update(client.GetIdentifier(), client);

                    return principal;
                }
            }

            return SentinelPrincipal.Anonymous;
        }

        /// <summary>
        /// Authenticates the client. Used when authenticating with the client_credentials grant type.
        /// </summary>
        /// <param name="clientId">The client id.</param>
        /// <param name="scope">The redirect URI.</param>
        /// <returns>The client principal.</returns>
        public override async Task<ISentinelPrincipal> AuthenticateClientAsync(string clientId, IEnumerable<string> scope)
        {
            var client = await this.ClientRepository.GetClient(clientId);

            if (client != null && client.Enabled)
            {
                var principal =
                        new SentinelPrincipal(
                            new SentinelIdentity(
                                AuthenticationType.OAuth,
                                new SentinelClaim(JwtClaimType.Name, clientId),
                                new SentinelClaim(ClaimType.RedirectUri, client.RedirectUri),
                                new SentinelClaim(ClaimType.Scope, string.Join(" ", scope)),
                                new SentinelClaim(ClaimTypes.AuthenticationMethod, AuthenticationMethod.ClientId)));

                if (principal.Identity.IsAuthenticated)
                {
                    client.LastUsed = DateTimeOffset.UtcNow;
                    await this.ClientRepository.Update(client.GetIdentifier(), client);

                    return principal;
                }
            }

            return SentinelPrincipal.Anonymous;
        }

        /// <summary>Authenticates the client using client id and secret.</summary>
        /// <param name="clientId">The client id.</param>
        /// <param name="clientSecret">The client secret.</param>
        /// <returns>The client principal.</returns>
        public override async Task<ISentinelPrincipal> AuthenticateClientCredentialsAsync(string clientId, string clientSecret)
        {
            var client = await this.ClientRepository.GetClient(clientId);

            if (client != null && client.Enabled)
            {
                if (this.CryptoProvider.ValidateHash(clientSecret, client.ClientSecret))
                {
                    var principal =
                        new SentinelPrincipal(
                            new SentinelIdentity(
                                AuthenticationType.OAuth,
                                new SentinelClaim(JwtClaimType.Name, client.ClientId),
                                new SentinelClaim(ClaimType.RedirectUri, client.RedirectUri),
                                new SentinelClaim(ClaimTypes.AuthenticationMethod, AuthenticationMethod.ClientCredentials)));

                    if (principal.Identity.IsAuthenticated)
                    {
                        client.LastUsed = DateTimeOffset.UtcNow;
                        await this.ClientRepository.Update(client.GetIdentifier(), client);

                        return principal;
                    }
                }
            }

            return SentinelPrincipal.Anonymous;
        }
    }
}