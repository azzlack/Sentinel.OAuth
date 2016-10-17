namespace Sentinel.OAuth.Middleware
{
    using Microsoft.Owin;
    using Microsoft.Owin.Security.Infrastructure;
    using Microsoft.Owin.Security.OAuth;

    public class BasicAuthenticationMiddleware : AuthenticationMiddleware<BasicAuthenticationOptions>
    {
        private readonly OAuthAuthorizationServerOptions oauthOptions;

        public BasicAuthenticationMiddleware(OwinMiddleware next, BasicAuthenticationOptions options, OAuthAuthorizationServerOptions oauthOptions)
            : base(next, options)
        {
            this.oauthOptions = oauthOptions;
        }

        /// <summary>Creates a handler for validating Basic auth requests.</summary>
        /// <returns>The new handler.</returns>
        protected override AuthenticationHandler<BasicAuthenticationOptions> CreateHandler()
        {
            return new BasicAuthenticationHandler(this.Options, this.oauthOptions);
        }
    }
}