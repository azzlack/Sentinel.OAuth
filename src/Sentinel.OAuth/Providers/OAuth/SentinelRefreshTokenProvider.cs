namespace Sentinel.OAuth.Providers.OAuth
{
    using Microsoft.Owin.Security;
    using Microsoft.Owin.Security.Infrastructure;
    using Sentinel.OAuth.Core.Constants.Identity;
    using Sentinel.OAuth.Core.Constants.OAuth;
    using Sentinel.OAuth.Core.Models;
    using Sentinel.OAuth.Extensions;
    using System;
    using System.Linq;
    using System.Threading.Tasks;

    /// <summary>The Sentinel refresh token provider.</summary>
    public class SentinelRefreshTokenProvider : AuthenticationTokenProvider
    {
        /// <summary>Options for controlling the operation.</summary>
        private readonly SentinelAuthorizationServerOptions options;

        /// <summary>
        ///     Initializes a new instance of the
        ///     Sentinel.OAuth.Core.Providers.SentinelRefreshTokenProvider class.
        /// </summary>
        /// <exception cref="ArgumentNullException">
        ///     Thrown when one or more required arguments are null.
        /// </exception>
        /// <param name="options">Options for controlling the operation.</param>
        public SentinelRefreshTokenProvider(SentinelAuthorizationServerOptions options)
        {
            if (options == null)
            {
                throw new ArgumentNullException("options");
            }

            this.options = options;

            this.OnCreate += this.CreateRefreshToken;
            this.OnReceive += this.ReceiveRefreshToken;
        }

        /// <summary>
        /// Creates a refresh token.
        /// </summary>
        /// <param name="context">The authentication context.</param>
        /// <returns/>
        public void CreateRefreshToken(AuthenticationTokenCreateContext context)
        {
            // Dont create a refresh token if it is a client_credentials request
            if (context.OwinContext.GetOAuthContext().GrantType == GrantType.ClientCredentials)
            {
                this.options.Logger.Debug("This is a client_credentials request, skipping refresh token creation.");

                return;
            }

            this.options.Logger.DebugFormat(
                "Creating refresh token for user '{0}', client id '{1}' and redirect uri '{2}'",
                context.Ticket.Identity.Name,
                context.OwinContext.GetOAuthContext().ClientId,
                context.OwinContext.GetOAuthContext().RedirectUri);

            var tcs = new TaskCompletionSource<string>();
            Task.Run(
                async () =>
                {
                    try
                    {
                        var createResult =
                            await
                            this.options.TokenManager.CreateRefreshTokenAsync(
                                context.Ticket.Identity.AsSentinelPrincipal(),
                                this.options.RefreshTokenLifetime,
                                context.OwinContext.GetOAuthContext().ClientId,
                                context.OwinContext.GetOAuthContext().RedirectUri,
                                context.OwinContext.GetOAuthContext().Scope);

                        tcs.SetResult(createResult.Token);
                    }
                    catch (Exception ex)
                    {
                        tcs.SetException(ex);
                    }
                }).ConfigureAwait(false);

            var refreshToken = tcs.Task.Result;

            context.SetToken(refreshToken);

            this.options.Logger.Debug("Created refresh token");
        }

        /// <summary>
        /// Authenticates a refresh token.
        /// </summary>
        /// <param name="context">The authentication context.</param>
        /// <returns/>
        public void ReceiveRefreshToken(AuthenticationTokenReceiveContext context)
        {
            this.options.Logger.Debug("Received refresh token");

            var clientId = context.OwinContext.GetOAuthContext().ClientId;
            var redirectUri = context.OwinContext.GetOAuthContext().RedirectUri;

            var tcs = new TaskCompletionSource<AuthenticationTicket>();
            Task.Run(
                async () =>
                {
                    try
                    {
                        var principal = await this.options.TokenManager.AuthenticateRefreshTokenAsync(clientId, redirectUri, context.Token);

                        if (principal.Identity.IsAuthenticated)
                        {
                            var client = principal.Identity.Claims.First(x => x.Type == ClaimType.Client);
                            var redirect = principal.Identity.Claims.First(x => x.Type == ClaimType.RedirectUri);
                            var scope = principal.Identity.Claims.FirstOrDefault(x => x.Type == ClaimType.Scope);

                            /* Override the validation parameters.
                             * This is because OWIN thinks the principal.Identity.Name should 
                             * be the same as the client_id from ValidateClientAuthentication method,
                             * but we need to use the user id in Sentinel.
                             */
                            var props = new AuthenticationProperties();
                            props.Dictionary.Add("client_id", client.Value);
                            props.RedirectUri = redirectUri;
                            props.ExpiresUtc = DateTimeOffset.UtcNow.Add(this.options.RefreshTokenLifetime);

                            // Re-authenticate user to get new claims
                            var user = await this.options.UserManager.AuthenticateUserAsync(principal.Identity.Name);

                            // Make sure the user has the correct claims
                            user.Identity.RemoveClaim(x => x.Type == ClaimType.Client);
                            user.Identity.RemoveClaim(x => x.Type == ClaimType.RedirectUri);
                            user.Identity.AddClaim(ClaimType.Client, client.Value);
                            user.Identity.AddClaim(ClaimType.RedirectUri, redirect.Value);

                            if (scope != null)
                            {
                                foreach (var s in scope.Value.Split(' '))
                                {
                                    user.Identity.AddClaim(ClaimType.Scope, s);
                                }
                            }

                            tcs.SetResult(new AuthenticationTicket(user.Identity.AsClaimsIdentity(), props));
                        }
                        else
                        {
                            tcs.SetResult(null);
                        }
                    }
                    catch (Exception ex)
                    {
                        tcs.SetException(ex);
                    }
                }).ConfigureAwait(false);

            var result = tcs.Task.Result;

            if (result != null)
            {
                context.SetTicket(result);
            }

            this.options.Logger.Debug("Finished processing refresh token");
        }
    }
}