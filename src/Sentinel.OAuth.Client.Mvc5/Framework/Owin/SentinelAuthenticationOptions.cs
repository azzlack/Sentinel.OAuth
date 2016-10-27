namespace Sentinel.OAuth.Client.Mvc5.Framework.Owin
{
    using System;
    using System.Collections.Generic;
    using System.ComponentModel;
    using System.Net.Http;

    using Microsoft.Owin.Infrastructure;
    using Microsoft.Owin.Logging;
    using Microsoft.Owin.Security;

    using Sentinel.OAuth.Client.Models;
    using Sentinel.OAuth.Core.Interfaces.Models;

    public class SentinelAuthenticationOptions : AuthenticationOptions
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="SentinelAuthenticationOptions" /> class.
        /// </summary>
        /// <param name="authenticationServerUrl">The authentication server url.</param>
        /// <param name="clientId">Identifier for the client.</param>
        /// <param name="clientSecret">The client secret.</param>
        /// <param name="redirectUri">URI of the redirect.</param>
        public SentinelAuthenticationOptions(string authenticationServerUrl, string clientId, string clientSecret, string redirectUri)
            : base(Constants.DefaultAuthenticationType)
        {
            this.AuthenticationServerUrl = authenticationServerUrl;
            this.ClientId = clientId;
            this.ClientSecret = clientSecret;
            this.RedirectUri = redirectUri;
            this.Scope = new List<string>();
            this.CookieConfiguration = new CookieConfiguration()
                                           {
                                               Name = clientId
                                           };
            this.Events = new AuthenticationEvents();
            this.TicketHandler = new TicketHandler();
            this.Endpoints = new AuthenticationEndpoints()
                                 {
                                     AuthorizationCodeEndpointUrl = $"{this.AuthenticationServerUrl}/oauth/authorize",
                                     TokenEndpointUrl = $"{this.AuthenticationServerUrl}/oauth/token",
                                     IdentityEndpointUrl = $"{this.AuthenticationServerUrl}/openid/userinfo"
                                };
        }

        internal ILogger Logger { get; set; }

        internal HttpClient Backchannel { get; set; }

        public string AuthenticationServerUrl { get; }

        public string ClientId { get; }

        public string ClientSecret { get; }

        public string RedirectUri { get; }

        /// <summary>A list of permissions to request.</summary>
        /// <value>The scope.</value>
        public ICollection<string> Scope { get; private set; }

        public TimeSpan RefreshTokenLifetime { get; set; }

        /// <summary>Gets or sets the endpoints.</summary>
        /// <value>The endpoints.</value>
        public IAuthenticationEndpoints Endpoints { get; set; }

        /// <summary>Gets or sets the cookie configuration.</summary>
        /// <value>The cookie configuration.</value>
        public CookieConfiguration CookieConfiguration { get; set; }

        /// <summary>Gets the events.</summary>
        /// <value>The events.</value>
        public AuthenticationEvents Events { get; set; }

        /// <summary>Gets the ticket handler.</summary>
        /// <value>The ticket handler.</value>
        public TicketHandler TicketHandler { get; set; }

        /// <summary>Gets or sets the backchannel HTTP handler.</summary>
        /// <value>The backchannel HTTP handler.</value>
        public HttpMessageHandler BackchannelHttpHandler { get; set; }

        /// <summary>Gets or sets the type used to secure data handled by the middleware.</summary>
        /// <value>The state data format.</value>
        public ISecureDataFormat<AuthenticationProperties> StateDataFormat { get; set; }

        [EditorBrowsable(EditorBrowsableState.Never)]
        internal ISystemClock SystemClock => new SystemClock();
    }
}