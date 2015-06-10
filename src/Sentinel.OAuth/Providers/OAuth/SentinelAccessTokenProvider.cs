namespace Sentinel.OAuth.Providers.OAuth
{
    using System;
    using System.Linq;
    using System.Security.Claims;
    using System.Threading.Tasks;

    using Microsoft.Owin.Security;
    using Microsoft.Owin.Security.Infrastructure;

    using Sentinel.OAuth.Core.Constants.Identity;
    using Sentinel.OAuth.Core.Constants.OAuth;
    using Sentinel.OAuth.Core.Models;
    using Sentinel.OAuth.Extensions;

    /// <summary>The Sentinel access token provider.</summary>
    public class SentinelAccessTokenProvider : AuthenticationTokenProvider
    {
        /// <summary>Options for controlling the operation.</summary>
        private readonly SentinelAuthorizationServerOptions options;

        /// <summary>
        ///     Initializes a new instance of the
        ///     Sentinel.OAuth.Core.Providers.SentinelAccessTokenProvider class.
        /// </summary>
        /// <exception cref="ArgumentNullException">
        ///     Thrown when one or more required arguments are null.
        /// </exception>
        /// <param name="options">Options for controlling the operation.</param>
        public SentinelAccessTokenProvider(SentinelAuthorizationServerOptions options)
        {
            if (options == null)
            {
                throw new ArgumentNullException("options");
            }

            this.options = options;

            this.OnCreate += this.CreateAccessToken;
            this.OnReceive += this.ReceiveAccessToken;
        }

        /// <summary>
        /// Creates an access token.
        /// </summary>
        /// <param name="context">The authentication context.</param>
        /// <returns/>
        private void CreateAccessToken(AuthenticationTokenCreateContext context)
        {
            string accessToken;

            if (context.OwinContext.GetOAuthContext().GrantType == GrantType.ClientCredentials)
            {
                this.options.Logger.DebugFormat(
                    "Creating access token for client '{0}' and scope '{1}'",
                    context.Ticket.Identity.Name,
                    string.Join(", ", context.OwinContext.GetOAuthContext().Scope));

                var tcs = new TaskCompletionSource<string>();
                Task.Run(
                    async () =>
                    {
                        try
                        {
                            var token =
                                await
                                this.options.TokenManager.CreateAccessTokenAsync(
                                    context.Ticket.Identity.AsSentinelPrincipal(),
                                    this.options.AccessTokenLifetime,
                                    context.OwinContext.GetOAuthContext().ClientId,
                                    context.OwinContext.GetOAuthContext().RedirectUri,
                                    context.OwinContext.GetOAuthContext().Scope);

                            tcs.SetResult(token);
                        }
                        catch (Exception ex)
                        {
                            tcs.SetException(ex);
                        }
                    }).ConfigureAwait(false);

                accessToken = tcs.Task.Result;
            }
            else
            {
                this.options.Logger.DebugFormat(
                    "Creating access token for user '{0}', client id '{1}' and redirect uri '{2}'",
                    context.Ticket.Identity.Name,
                    context.OwinContext.GetOAuthContext().ClientId,
                    context.OwinContext.GetOAuthContext().RedirectUri);

                // Add expiration claim so it is stored with the token
                context.Ticket.Identity.AddClaim(new Claim(ClaimTypes.Expiration, DateTime.UtcNow.Add(this.options.AccessTokenLifetime).ToUnixTime().ToString()));

                var tcs = new TaskCompletionSource<string>();
                Task.Run(
                    async () =>
                    {
                        try
                        {
                            var token =
                                await
                                this.options.TokenManager.CreateAccessTokenAsync(
                                    context.Ticket.Identity.AsSentinelPrincipal(),
                                    this.options.AccessTokenLifetime,
                                    context.OwinContext.GetOAuthContext().ClientId,
                                    context.OwinContext.GetOAuthContext().RedirectUri,
                                    context.OwinContext.GetOAuthContext().Scope);

                            tcs.SetResult(token);
                        }
                        catch (Exception ex)
                        {
                            tcs.SetException(ex);
                        }
                    }).ConfigureAwait(false);

                accessToken = tcs.Task.Result;
            }

            context.Ticket.Identity.AddClaim(new Claim(ClaimType.AccessToken, accessToken));

            context.SetToken(accessToken);

            this.options.Logger.DebugFormat("Created access token");
        }

        /// <summary>
        /// Authenticates an access token.
        /// </summary>
        /// <param name="context">The authentication context.</param>
        /// <returns/>
        private void ReceiveAccessToken(AuthenticationTokenReceiveContext context)
        {
            this.options.Logger.DebugFormat("Received access token");

            var tcs = new TaskCompletionSource<AuthenticationTicket>();
            Task.Run(
                async () =>
                {
                    try
                    {
                        var principal = await this.options.TokenManager.AuthenticateAccessTokenAsync(context.Token);

                        if (principal.Identity.IsAuthenticated)
                        {
                            var props = new AuthenticationProperties
                                            {
                                                ExpiresUtc = DateTimeOffset.UtcNow.Add(this.options.AccessTokenLifetime)
                                            };

                            /* Override the validation parameters.
                             * This is because OWIN thinks the principal.Identity.Name should 
                             * be the same as the client_id from ValidateClientAuthentication method,
                             * but we need to use the user id in Sentinel.
                             */
                            if (principal.Identity.HasClaim(x => x.Type == ClaimType.Client))
                            {
                                props.Dictionary.Add("client_id", principal.Identity.Claims.First(x => x.Type == ClaimType.Client).Value);
                            }

                            tcs.SetResult(new AuthenticationTicket(principal.Identity.AsClaimsIdentity(), props));
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

            this.options.Logger.Debug("Finished processing access token");
        }
    }
}