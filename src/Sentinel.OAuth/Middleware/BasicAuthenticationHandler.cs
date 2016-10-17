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

    public class BasicAuthenticationHandler : AuthenticationHandler<BasicAuthenticationOptions>
    {
        /// <summary>Options for controlling the operation.</summary>
        private readonly BasicAuthenticationOptions options;

        /// <summary>Initializes a new instance of the <see cref="BasicAuthenticationHandler" /> class.</summary>
        /// <param name="options">Options for controlling the operation.</param>
        public BasicAuthenticationHandler(BasicAuthenticationOptions options)
        {
            this.options = options;
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

            if (this.options.RequireSecureConnection && !this.Request.IsSecure)
            {
                throw new AuthenticationException("Basic authentication requires a secure connection");
            }

            this.options.Logger.Debug("Authenticating user using Basic authentication");

            var parameter = authorizationHeader.Substring(5).Trim();
            var digest = this.ParseParameter(parameter);

            var identity = await this.GetIdentity(digest);

            if (identity.IsAuthenticated)
            {

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

        private BasicAuthenticationDigest ParseParameter(string parameter)
        {
            var decoded = Encoding.UTF8.GetString(Convert.FromBase64String(parameter));

            var username = decoded.Split(':')[0];
            var key = decoded.Split(':')[1];

            return new BasicAuthenticationDigest(username, key);
        }
        
        /// <summary>Gets the identity for the specified credentials.</summary>
        /// <param name="credentials">The credentials.</param>
        /// <returns>The identity.</returns>
        private async Task<ISentinelIdentity> GetIdentity(BasicAuthenticationDigest credentials)
        {
            // See if the digest represents an application
            var client = await this.options.ClientManager.AuthenticateClientCredentialsAsync(credentials);
            if (client.Identity.IsAuthenticated)
            {
                return client.Identity;
            }

            var user = await this.options.UserManager.AuthenticateUserWithApiKeyAsync(credentials);
            if (user.Identity.IsAuthenticated)
            {
                return user.Identity;
            }

            return SentinelIdentity.Anonymous;
        }
    }
}