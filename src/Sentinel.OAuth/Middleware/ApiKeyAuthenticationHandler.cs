namespace Sentinel.OAuth.Middleware
{
    using System;
    using System.Runtime.Caching;
    using System.Security.Authentication;
    using System.Text;
    using System.Threading.Tasks;

    using Microsoft.Owin;
    using Microsoft.Owin.Security;
    using Microsoft.Owin.Security.Infrastructure;

    using Sentinel.OAuth.Core.Extensions;
    using Sentinel.OAuth.Core.Interfaces.Identity;
    using Sentinel.OAuth.Core.Models;
    using Sentinel.OAuth.Extensions;
    using Sentinel.OAuth.Models.Identity;

    public class ApiKeyAuthenticationHandler : AuthenticationHandler<ApiKeyAuthenticationOptions>
    {
        /// <summary>Options for controlling the operation.</summary>
        private readonly ApiKeyAuthenticationOptions options;

        /// <summary>The nonces.</summary>
        private readonly ObjectCache nonces;

        /// <summary>Initializes a new instance of the <see cref="ApiKeyAuthenticationHandler" /> class.</summary>
        /// <param name="options">Options for controlling the operation.</param>
        public ApiKeyAuthenticationHandler(ApiKeyAuthenticationOptions options)
        {
            this.options = options;
            this.nonces = MemoryCache.Default;
        }

        /// <summary>
        /// The core authentication logic which must be provided by the handler. Will be invoked at most
        ///             once per request. Do not call directly, call the wrapping Authenticate method instead.
        /// </summary>
        /// <returns>
        /// The ticket data provided by the authentication logic
        /// </returns>
        protected override async Task<AuthenticationTicket> AuthenticateCoreAsync()
        {
            var authorizationHeader = this.Request.Headers.Get("Authorization");

            if (string.IsNullOrEmpty(authorizationHeader)
                || !authorizationHeader.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase)
                || this.Request.Path == new PathString("/oauth/token")
                || this.Request.Path == new PathString("/oauth/authorize"))
            {
                return new AuthenticationTicket(null, new AuthenticationProperties());
            }

            if (!this.Request.IsSecure)
            {
                throw new AuthenticationException("Basic authentication requires a secure connection");
            }

            this.options.Logger.Debug("Authenticating user using API key and Basic authentication");

            var parameter = authorizationHeader.Substring(5).Trim();
            var digest = this.ParseParameter(parameter);

            if (digest == null || !this.ValidateDigest(digest))
            {
                throw new AuthenticationException("Invalid digest");
            }

            var identity = await this.GetIdentity(digest);

            if (identity.IsAuthenticated)
            {
                // NOTE: Must add Client claim fully validate the user
                identity.AddClaim(global::Sentinel.OAuth.Core.Constants.Identity.ClaimType.Client, digest.ClientId);

                // Validate ticket
                var ticket = new AuthenticationTicket(identity.ToClaimsIdentity(), new AuthenticationProperties());

                this.options.Logger.Debug($"User '{identity.Name}' was successfully authenticated");

                return ticket;
            }

            this.options.Logger.WarnFormat("User could not be authenticated");

            // Add challenge to response
            this.Response.Headers.AppendValues("WWW-Authenticate", $"Basic realm={this.options.Realm}");

            return new AuthenticationTicket(null, new AuthenticationProperties());
        }

        /// <summary>Parses the parameter</summary>
        /// <param name="parameter">The parameter.</param>
        /// <returns>The parsed parameter.</returns>
        private ApiKeyAuthenticationDigest ParseParameter(string parameter)
        {
            // Decode and split parameter into username and digest
            string decodedParameter;

            try
            {
                decodedParameter = Encoding.UTF8.GetString(Convert.FromBase64String(parameter));
            }
            catch (FormatException)
            {
                this.options.Logger.Warn("The Basic parameter is not Base-64 encoded");

                return null;
            }

            var splitParameter = decodedParameter.Split(':');
            if (splitParameter.Length != 2)
            {
                this.options.Logger.Warn("The Basic parameter is invalid");

                return null;
            }

            // Decode and split digest into client id, redirect uri, request url, timestamp, nonce and signature
            string decodedDigest;
            try
            {
                decodedDigest = Encoding.UTF8.GetString(Convert.FromBase64String(splitParameter[1]));
            }
            catch (FormatException)
            {
                this.options.Logger.Warn("The token is not Base-64 encoded");

                return null;
            }

            var splitDigest = decodedDigest.Split(',');
            if (splitDigest.Length != 6)
            {
                this.options.Logger.Warn("The digest is invalid");

                return null;
            }

            try
            {
                var userId = splitParameter[0];
                var clientId = splitDigest[0].Substring(splitDigest[0].IndexOf('=') + 1);
                var redirectUri = splitDigest[1].Substring(splitDigest[1].IndexOf('=') + 1);
                var requestUrl = new Uri(splitDigest[2].Substring(splitDigest[2].IndexOf('=') + 1));
                long timestamp;
                long.TryParse(splitDigest[3].Substring(splitDigest[3].IndexOf('=') + 1), out timestamp);
                var nonce = splitDigest[4].Substring(splitDigest[4].IndexOf('=') + 1);
                var signature = splitDigest[5].Substring(splitDigest[5].IndexOf('=') + 1);

                return new ApiKeyAuthenticationDigest(userId, clientId, redirectUri, requestUrl, timestamp, nonce, signature);
            }
            catch (Exception ex)
            {
                this.options.Logger.Warn($"Could not parse properties: {splitParameter[0]}:{decodedDigest}", ex);

                return null;
            }
        }

        private bool ValidateDigest(ApiKeyAuthenticationDigest digest)
        {
            // 1. Validate timestamp is within boundaries
            var serverTimestamp = DateTimeOffset.UtcNow.ToUnixTime();

            if (digest.Timestamp > (serverTimestamp + this.options.MaximumClockSkew.TotalSeconds)
                || digest.Timestamp < (serverTimestamp - this.options.MaximumClockSkew.TotalSeconds))
            {
                this.options.Logger.Warn("The request timestamp is outside the allowed boundaries");

                return false;
            }

            // 2. Validate nonce has not been used before in the last 5 minutes
            if (this.nonces.Contains($"{digest.ClientId}_{digest.Nonce}"))
            {
                this.options.Logger.Warn("The nonce has been used recently");

                return false;
            }
            else
            {
                this.nonces.Add($"{digest.ClientId}_{digest.Nonce}", digest, DateTimeOffset.UtcNow.Add(this.options.MaximumClockSkew));
            }

            return true;
        }

        /// <summary>Gets the identity for the specified credentials.</summary>
        /// <param name="credentials">The credentials.</param>
        /// <returns>The identity.</returns>
        private async Task<ISentinelIdentity> GetIdentity(ApiKeyAuthenticationDigest credentials)
        {
            // Validate client
            var client = await this.options.ClientManager.AuthenticateClientAsync(credentials.ClientId, credentials.RedirectUri);

            if (!client.Identity.IsAuthenticated)
            {
                return SentinelIdentity.Anonymous;
            }

            // Validate user
            var user = await this.options.UserManager.AuthenticateUserWithApiKeyAsync(credentials);

            if (!user.Identity.IsAuthenticated)
            {
                return SentinelIdentity.Anonymous;
            }

            return user.Identity;
        }
    }
}