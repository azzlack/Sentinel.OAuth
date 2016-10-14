namespace Sentinel.OAuth.Extensions
{
    using Common.Logging;
    using Microsoft.Owin;
    using Microsoft.Owin.Security.OAuth;
    using Owin;
    using Sentinel.OAuth.Core.Constants;
    using Sentinel.OAuth.Core.Models;
    using Sentinel.OAuth.Implementation.Managers;
    using Sentinel.OAuth.Implementation.Providers;
    using Sentinel.OAuth.Implementation.Repositories;
    using Sentinel.OAuth.Middleware;
    using Sentinel.OAuth.Models.Providers;
    using Sentinel.OAuth.Providers.OAuth;
    using System;

    using Sentinel.OAuth.Core.Interfaces.Managers;

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
                throw new ArgumentNullException(nameof(app));
            }

            // Last minute default configurations
            if (options.Logger == null)
            {
                options.Logger = LogManager.GetLogger("Sentinel.OAuth");
            }

            if (options.IssuerUri == null)
            {
                throw new InvalidOperationException("IssuerUri must be set");
            }

            if (options.TokenCryptoProvider == null)
            {
                options.TokenCryptoProvider = new SHA2CryptoProvider(HashAlgorithm.SHA256);
            }

            if (options.PasswordCryptoProvider == null)
            {
                options.PasswordCryptoProvider = new PBKDF2CryptoProvider();
            }

            if (options.ApiKeyCryptoProvider == null)
            {
                options.ApiKeyCryptoProvider = new AsymmetricCryptoProvider();
            }

            if (options.PrincipalProvider == null)
            {
                options.PrincipalProvider = new PrincipalProvider(options.TokenCryptoProvider);
            }

            if (options.UserRepository == null && options.UserManager == null)
            {
                throw new InvalidOperationException("UserRepository must be set if not using a specific UserManager");
            }

            if (options.ClientRepository == null && options.ClientManager == null)
            {
                throw new InvalidOperationException("ClientRepository must be set if not using a specific ClientManager");
            }

            if (options.TokenRepository == null)
            {
                options.TokenRepository = new MemoryTokenRepository();
            }

            if (options.TokenProvider == null)
            {
                options.TokenProvider = new JwtTokenProvider(new JwtTokenProviderConfiguration(options.TokenCryptoProvider, options.IssuerUri, options.TokenCryptoProvider.CreateHash(256)));
            }

            if (options.TokenManager == null)
            {
                options.TokenManager = new TokenManager(options.Logger, options.PrincipalProvider, options.TokenProvider, options.TokenRepository);
            }

            if (options.UserManager == null && options.UserRepository != null)
            {
                options.UserManager = new UserManager(options.PasswordCryptoProvider, options.ApiKeyCryptoProvider, options.UserRepository, options.UserApiKeyRepository);
            }

            if (options.ClientManager == null && options.ClientRepository != null)
            {
                options.ClientManager = new ClientManager(options.PasswordCryptoProvider, options.ClientRepository);
            }

            // Initialize basic auth if specified
            if (options.EnableBasicAuthentication)
            {
                var basicAuthenticationOptions = new BasicAuthenticationOptions()
                {
                    ClientManager = options.ClientManager,
                    UserManager = options.UserManager,
                    Logger = options.Logger,
                    Realm = options.Realm
                };
                app.Use<BasicAuthenticationMiddleware>(basicAuthenticationOptions);
            }

            if (options.EnableApiKeyAuthentication)
            {
                var basicAuthenticationOptions = new ApiKeyAuthenticationOptions()
                {
                    ClientManager = options.ClientManager,
                    UserManager = options.UserManager,
                    Logger = options.Logger,
                    Realm = options.Realm,
                    MaximumClockSkew = options.MaximumClockSkew
                };
                app.Use<ApiKeyAuthenticationMiddleware>(basicAuthenticationOptions);
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

            // Set up identity endpoint
            app.Map(options.IdentityEndpointUrl, config => config.Use<UserInfoMiddleware>());

            return app;
        }
    }
}