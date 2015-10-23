namespace Sentinel.OAuth.Extensions
{
    using Common.Logging;
    using Microsoft.Owin;
    using Microsoft.Owin.Security.OAuth;
    using Newtonsoft.Json;
    using Owin;
    using Sentinel.OAuth.Core.Constants.OAuth;
    using Sentinel.OAuth.Core.Models;
    using Sentinel.OAuth.Core.Models.OAuth.Http;
    using Sentinel.OAuth.Implementation.Managers;
    using Sentinel.OAuth.Implementation.Providers;
    using Sentinel.OAuth.Implementation.Repositories;
    using Sentinel.OAuth.Models.Providers;
    using Sentinel.OAuth.Providers.OAuth;
    using System;
    using System.Net;

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

            if (options.IssuerUri == null)
            {
                throw new InvalidOperationException("IssuerUri must be set");
            }

            if (options.TokenCryptoProvider == null)
            {
                options.TokenCryptoProvider = new SHA2CryptoProvider();
            }

            if (options.PasswordCryptoProvider == null)
            {
                options.PasswordCryptoProvider = new PBKDF2CryptoProvider();
            }

            if (options.PrincipalProvider == null)
            {
                options.PrincipalProvider = new PrincipalProvider(options.TokenCryptoProvider);
            }

            if (options.UserRepository == null)
            {
                throw new InvalidOperationException("UserRepository must be set");
            }

            if (options.ClientRepository == null)
            {
                throw new InvalidOperationException("ClientRepository must be set");
            }

            if (options.TokenRepository == null)
            {
                options.TokenRepository = new MemoryTokenRepository();
            }

            if (options.TokenProvider == null)
            {
                options.TokenProvider = new JwtTokenProvider(new JwtTokenProviderConfiguration(options.IssuerUri, options.TokenCryptoProvider.CreateHash(256)));
            }

            if (options.TokenManager == null)
            {
                options.TokenManager = new TokenManager(options.Logger, options.UserManager, options.PrincipalProvider, options.TokenProvider, options.TokenRepository, options.ClientRepository);
            }

            if (options.UserManager == null)
            {
                options.UserManager = new UserManager(options.PasswordCryptoProvider, options.UserRepository);
            }

            if (options.ClientManager == null)
            {
                options.ClientManager = new ClientManager(options.PasswordCryptoProvider, options.ClientRepository);
            }

            if (options.UserManager == null)
            {
                throw new InvalidOperationException("UserManager must be set");
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
            app.Map(
                options.IdentityEndpointUrl,
                config =>
                    {
                        config.Run(
                            async (context) =>
                                {
                                    var auth = await context.Authentication.AuthenticateAsync(OAuthDefaults.AuthenticationType);

                                    if (auth != null && auth.Identity.IsAuthenticated)
                                    {
                                        context.Response.ContentType = "application/json";
                                        await context.Response.WriteAsync(JsonConvert.SerializeObject(new IdentityResponse(auth.Identity.AsSentinelIdentity())));
                                    }
                                    else
                                    {
                                        context.Response.StatusCode = (int)HttpStatusCode.Unauthorized;
                                        context.Response.ContentType = "application/json";
                                        context.Response.Headers["WWW-Authenticate"] = "";
                                        await context.Response.WriteAsync(JsonConvert.SerializeObject(new ErrorResponse(ErrorCode.InvalidToken)));
                                    }
                                });
                    });

            return app;
        }
    }
}