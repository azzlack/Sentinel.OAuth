namespace Sentinel.OAuth.Providers.OAuth
{
    using System;
    using System.Linq;
    using System.Security.Claims;
    using System.Threading.Tasks;

    using Microsoft.Owin.Security;
    using Microsoft.Owin.Security.Infrastructure;

    using Sentinel.OAuth.Core.Constants.Identity;
    using Sentinel.OAuth.Core.Models;
    using Sentinel.OAuth.Extensions;
    using Sentinel.OAuth.Models.Identity;

    /// <summary>The Sentinel authorization code provider.</summary>
    public class SentinelAuthorizationCodeProvider : AuthenticationTokenProvider
    {
        /// <summary>Options for controlling the operation.</summary>
        private readonly SentinelAuthorizationServerOptions options;

        /// <summary>
        ///     Initializes a new instance of the
        ///     Sentinel.OAuth.Core.Providers.SentinelAuthorizationCodeProvider class.
        /// </summary>
        /// <exception cref="ArgumentNullException">
        ///     Thrown when one or more required arguments are null.
        /// </exception>
        /// <param name="options">Options for controlling the operation.</param>
        public SentinelAuthorizationCodeProvider(SentinelAuthorizationServerOptions options)
        {
            if (options == null)
            {
                throw new ArgumentNullException("options");
            }

            this.options = options;

            this.OnCreate += this.CreateAuthenticationCode;
            this.OnReceive += this.ReceiveAuthenticationCode;
        }

        /// <summary>
        /// Creates an authorization code.
        /// </summary>
        /// <param name="context">The authentication context.</param>
        /// <returns/>
        public void CreateAuthenticationCode(AuthenticationTokenCreateContext context)
        {
            this.options.Logger.DebugFormat("Creating authorization code for client '{0}' and redirect uri '{1}'", context.Request.Query["client_id"], context.Request.Query["redirect_uri"]);

            var tcs = new TaskCompletionSource<string>();
            Task.Run(
                async () =>
                {
                    try
                    {
                        var identity = new SentinelIdentity(AuthenticationType.OAuth, context.Ticket.Identity.Claims.Select(x => new SentinelClaim(x.Type, x.Value)).ToArray());
                        
                        // Overwrite client claim
                        identity.RemoveClaim(x => x.Type == ClaimType.Client);
                        identity.AddClaim(ClaimType.Client, context.Request.Query["client_id"]);

                        // Generate code
                        var createResult =
                            await
                            this.options.TokenManager.CreateAuthorizationCodeAsync(
                                new SentinelPrincipal(identity), 
                                this.options.AuthorizationCodeLifetime,
                                context.Request.Query["redirect_uri"],
                                !string.IsNullOrEmpty(context.Request.Query["scope"])
                                    ? context.Request.Query["scope"].Split(' ')
                                    : null);

                        tcs.SetResult(createResult.Token);
                    }
                    catch (Exception ex)
                    {
                        tcs.SetException(ex);
                    }
                }).ConfigureAwait(false);

            context.SetToken(tcs.Task.Result);

            this.options.Logger.Debug("Created authorization code");
        }

        /// <summary>
        /// Authenticates a refresh token.
        /// </summary>
        /// <param name="context">The authentication context.</param>
        /// <returns/>
        public void ReceiveAuthenticationCode(AuthenticationTokenReceiveContext context)
        {
            var tcs = new TaskCompletionSource<AuthenticationTicket>();
            Task.Run(
                async () =>
                {
                    try
                    {
                        var parameters = await context.Request.ReadFormAsync();

                        this.options.Logger.DebugFormat("Validating authorization code for redirect uri '{0}'", parameters["redirect_uri"]);

                        var principal =
                            await
                            this.options.TokenManager.AuthenticateAuthorizationCodeAsync(
                                parameters["redirect_uri"],
                                context.Token);

                        if (principal.Identity.IsAuthenticated)
                        {
                            this.options.Logger.Debug("Authorization code is valid");

                            /* Override the validation parameters.
                             * This is because OWIN thinks the principal.Identity.Name should 
                             * be the same as the client_id from ValidateClientAuthentication method,
                             * but we need to use the user id in Sentinel.
                             */
                            var props = new AuthenticationProperties();
                            props.Dictionary.Add("client_id", principal.Identity.Claims.First(x => x.Type == ClaimType.Client).Value);
                            props.RedirectUri = parameters["redirect_uri"];
                            props.ExpiresUtc = DateTimeOffset.UtcNow.Add(this.options.AuthorizationCodeLifetime);

                            tcs.SetResult(new AuthenticationTicket(principal.Identity.AsClaimsIdentity(), props));
                        }
                        else
                        {
                            this.options.Logger.Warn("Authorization code is not valid");

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
        }
    }
}