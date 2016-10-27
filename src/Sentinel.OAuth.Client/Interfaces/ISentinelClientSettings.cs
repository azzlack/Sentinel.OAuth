namespace Sentinel.OAuth.Client.Interfaces
{
    using System;

    using Sentinel.OAuth.Client.Models;
    using Sentinel.OAuth.Core.Interfaces.Models;

    public interface ISentinelClientSettings
    {
        /// <summary>
        /// Gets the URL.
        /// </summary>
        /// <value>The URL.</value>
        Uri Url { get; }

        /// <summary>
        /// Gets the client id.
        /// </summary>
        /// <value>The client id.</value>
        string ClientId { get; }

        /// <summary>
        /// Gets the client secret.
        /// </summary>
        /// <value>The client secret.</value>
        string ClientSecret { get; }

        /// <summary>
        /// Gets the redirect URI.
        /// </summary>
        /// <value>The redirect URI.</value>
        string RedirectUri { get; }

        /// <summary>
        /// Gets the refresh token lifetime.
        /// </summary>
        /// <value>The refresh token lifetime.</value>
        TimeSpan RefreshTokenLifetime { get; }

        /// <summary>Gets the endpoints.</summary>
        /// <value>The endpoints.</value>
        IAuthenticationEndpoints Endpoints { get; }
    }
}