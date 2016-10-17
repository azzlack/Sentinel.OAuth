namespace Sentinel.OAuth.Client
{
    using System;

    using Sentinel.OAuth.Client.Interfaces;
    using Sentinel.OAuth.Client.Models;

    public class SentinelClientSettings : ISentinelClientSettings
    {
        /// <summary>
        /// Initializes a new instance of the Sentinel.OAuth.Client.SentinelClientSettings class.
        /// </summary>
        /// <param name="uri">URI of the document.</param>
        /// <param name="clientId">Identifier for the client.</param>
        /// <param name="clientSecret">The client secret.</param>
        /// <param name="redirectUri">URI of the redirect.</param>
        /// <param name="refreshTokenLifetime">The refresh token lifetime.</param>
        /// <param name="endpoints">The endpoints.</param>
        public SentinelClientSettings(Uri uri, string clientId, string clientSecret, string redirectUri, TimeSpan refreshTokenLifetime, AuthenticationEndpoints endpoints)
        {
            this.Url = uri;
            this.ClientId = clientId;
            this.ClientSecret = clientSecret;
            this.RedirectUri = redirectUri;
            this.RefreshTokenLifetime = refreshTokenLifetime;
            this.Endpoints = endpoints;
        }

        /// <summary>Gets the URL.</summary>
        /// <value>The URL.</value>
        public Uri Url { get; private set; }

        /// <summary>Gets the client id.</summary>
        /// <value>The client id.</value>
        public string ClientId { get; private set; }

        /// <summary>Gets the client secret.</summary>
        /// <value>The client secret.</value>
        public string ClientSecret { get; private set; }

        /// <summary>Gets the redirect URI.</summary>
        /// <value>The redirect URI.</value>
        public string RedirectUri { get; private set; }

        /// <summary>Gets the refresh token lifetime.</summary>
        /// <value>The refresh token lifetime.</value>
        public TimeSpan RefreshTokenLifetime { get; private set; }

        /// <summary>Gets the endpoints.</summary>
        /// <value>The endpoints.</value>
        public AuthenticationEndpoints Endpoints { get; private set; }
    }
}