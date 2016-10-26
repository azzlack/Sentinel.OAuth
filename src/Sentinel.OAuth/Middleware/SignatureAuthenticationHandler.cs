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
    using Microsoft.Owin.Security.OAuth;

    using Sentinel.OAuth.Core.Extensions;
    using Sentinel.OAuth.Core.Interfaces.Identity;
    using Sentinel.OAuth.Core.Models;
    using Sentinel.OAuth.Extensions;
    using Sentinel.OAuth.Models.Identity;

    public class SignatureAuthenticationHandler : AuthenticationHandler<SignatureAuthenticationOptions>
    {
        private readonly SignatureAuthenticationOptions options;

        private readonly OAuthAuthorizationServerOptions oauthOptions;

        /// <summary>The nonces.</summary>
        private readonly ObjectCache nonces;

        /// <summary>Initializes a new instance of the <see cref="SignatureAuthenticationHandler" /> class.</summary>
        /// <param name="options">Options for controlling the operation.</param>
        public SignatureAuthenticationHandler(SignatureAuthenticationOptions options, OAuthAuthorizationServerOptions oauthOptions)
        {
            this.options = options;
            this.oauthOptions = oauthOptions;
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
                || !authorizationHeader.StartsWith("Signature ", StringComparison.OrdinalIgnoreCase)
                || this.Request.Path == this.oauthOptions.TokenEndpointPath
                || this.Request.Path == this.oauthOptions.AuthorizeEndpointPath)
            {
                return new AuthenticationTicket(null, new AuthenticationProperties());
            }

            try
            {
                if (this.options.RequireSecureConnection && !this.Request.IsSecure)
                {
                    throw new AuthenticationException("Signature authentication requires a secure connection");
                }

                this.options.Logger.Debug("Authenticating using Signature authentication");

                var parameter = authorizationHeader.Substring(this.options.AuthenticationType.Length).Trim();
                var digest = this.ParseParameter(parameter);

                if (digest == null || !await this.ValidateDigest(digest))
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

                    this.options.Logger.Debug($"'{identity.Name}' was successfully authenticated");

                    return ticket;
                }

                this.options.Logger.WarnFormat("User could not be authenticated");
            }
            catch (Exception ex)
            {
                this.options.Logger.Error(ex);
            }

            // Add challenge to response
            this.Response.Headers.AppendValues("WWW-Authenticate", $"Signature realm={this.options.Realm}");

            return new AuthenticationTicket(null, new AuthenticationProperties());
        }

        /// <summary>Parses the parameter</summary>
        /// <param name="parameter">The parameter.</param>
        /// <returns>The parsed parameter.</returns>
        private SignatureAuthenticationDigest ParseParameter(string parameter)
        {
            // Decode and split parameter into username and digest
            string decodedParameter;

            try
            {
                decodedParameter = Encoding.UTF8.GetString(Convert.FromBase64String(parameter));
            }
            catch (FormatException)
            {
                this.options.Logger.Warn("The Signature parameter is not Base-64 encoded");

                return null;
            }

            var splitDigest = decodedParameter.Split(',');

            if (splitDigest.Length != 7)
            {
                throw new ArgumentException("The Signature is invalid");
            }

            try
            {
                var userId = splitDigest[0].Substring(splitDigest[0].IndexOf('=') + 1);
                var clientId = splitDigest[1].Substring(splitDigest[1].IndexOf('=') + 1);
                var redirectUri = splitDigest[2].Substring(splitDigest[2].IndexOf('=') + 1);
                var requestUrl = splitDigest[3].Substring(splitDigest[3].IndexOf('=') + 1);

                long timestamp;
                long.TryParse(splitDigest[4].Substring(splitDigest[4].IndexOf('=') + 1), out timestamp);

                var nonce = splitDigest[5].Substring(splitDigest[5].IndexOf('=') + 1);
                var signature = splitDigest[6].Substring(splitDigest[6].IndexOf('=') + 1);

                return new SignatureAuthenticationDigest(userId, clientId, redirectUri, requestUrl, timestamp, nonce, signature);
            }
            catch (Exception ex)
            {
                this.options.Logger.Warn($"Could not parse properties: {decodedParameter}", ex);

                return null;
            }
        }

        private async Task<bool> ValidateDigest(SignatureAuthenticationDigest digest)
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

            // 3. Validate client
            var client = await this.options.ClientManager.AuthenticateClientAsync(digest.ClientId, digest.RedirectUri);
            if (!client.Identity.IsAuthenticated)
            {
                return false;
            }

            // 4. Validate url
            if (!this.Request.IsSameUrl(digest.RequestUrl))
            {
                this.options.Logger.Warn($"The request_url parameter ({digest.RequestUrl}) does not match the requested url {this.Request.Uri}");

                return false;
            }

            return true;
        }

        /// <summary>Gets the identity for the specified credentials.</summary>
        /// <param name="credentials">The credentials.</param>
        /// <returns>The identity.</returns>
        private async Task<ISentinelIdentity> GetIdentity(SignatureAuthenticationDigest credentials)
        {
            if (credentials.ClientId == credentials.UserId)
            {
                // Validate client using api key
                var client = await this.options.ClientManager.AuthenticateClientWithSignatureAsync(credentials);
                if (client.Identity.IsAuthenticated)
                {
                    return client.Identity;
                }
            }

            try
            {
                // Validate user
                var user = await this.options.UserManager.AuthenticateUserWithSignatureAsync(credentials);
                if (user.Identity.IsAuthenticated)
                {
                    return user.Identity;
                }
            }
            catch (ArgumentException ex)
            {
                this.options.Logger.Error(ex);
            }

            return SentinelIdentity.Anonymous;
        }
    }
}