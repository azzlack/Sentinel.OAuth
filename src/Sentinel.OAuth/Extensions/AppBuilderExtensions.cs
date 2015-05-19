namespace Sentinel.OAuth.Extensions
{
    using System;

    using Common.Logging;

    using Microsoft.Owin;
    using Microsoft.Owin.Security.OAuth;

    using Owin;

    using Sentinel.OAuth.Core.Models;
    using Sentinel.OAuth.Implementation;
    using Sentinel.OAuth.Providers.OAuth;

    /// <summary>
    /// Extension methods to add Authorization Server capabilities to an OWIN pipeline
    /// </summary>
    public static class AppBuilderExtensions
    {
        /// <summary>
        /// Adds OAuth2 Authorization Server capabilities to an OWIN web application. This middleware
        /// performs the request processing for the Authorize and Token endpoints defined by the OAuth2 specification.
        /// See also http://tools.ietf.org/html/rfc6749
        /// </summary>
        /// <param name="app">The web application builder</param>
        /// <param name="options">Options which control the behavior of the Authorization Server.</param>
        /// <returns>The application builder</returns>
        public static IAppBuilder UseSentinelAuthorizationServer(this IAppBuilder app, SentinelAuthorizationServerOptions options)
        {
            if (app == null)
            {
                throw new ArgumentNullException("app");
            }

            // Last minute default configurations
            if (options.Logger == null)
            {
                options.Logger = LogManager.GetLogger("Sentinel.OAuth");
            }

            if (options.CryptoProvider == null)
            {
                options.CryptoProvider = new PBKDF2CryptoProvider();
            }

            if (options.PrincipalProvider == null)
            {
                options.PrincipalProvider = new PrincipalProvider(options.CryptoProvider);
            }

            if (options.TokenManager == null)
            {
                options.TokenManager = new TokenManager(options.Logger, options.UserManager, options.PrincipalProvider, options.CryptoProvider, new TokenFactory(), new MemoryTokenRepository());
            }

            // Initialize underlying OWIN OAuth system
            var oauthOptions = new OAuthAuthorizationServerOptions
            {
                AllowInsecureHttp = true,
                AccessTokenExpireTimeSpan = options.AccessTokenLifetime,
                AuthorizationCodeExpireTimeSpan = options.AuthorizationCodeLifetime,
                AuthorizeEndpointPath = new PathString(options.AuthorizationCodeEndpointUrl),
                TokenEndpointPath = new PathString(options.TokenEndpointUrl),
                Provider = new SentinelAuthorizationServerProvider(options),
                AccessTokenProvider = new SentinelAccessTokenProvider(options),
                AuthorizationCodeProvider = new SentinelAuthorizationCodeProvider(options),
                RefreshTokenProvider = new SentinelRefreshTokenProvider(options)
            };

            app.UseOAuthAuthorizationServer(oauthOptions);
            app.UseOAuthBearerAuthentication(new OAuthBearerAuthenticationOptions()
                                                 {
                                                     AccessTokenProvider = oauthOptions.AccessTokenProvider
                                                 });

            return app;
        }
    }
}