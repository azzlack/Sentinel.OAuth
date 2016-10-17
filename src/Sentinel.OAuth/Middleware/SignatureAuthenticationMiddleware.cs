namespace Sentinel.OAuth.Middleware
{
    using Microsoft.Owin;
    using Microsoft.Owin.Security.Infrastructure;
    using Microsoft.Owin.Security.OAuth;

    public class SignatureAuthenticationMiddleware : AuthenticationMiddleware<SignatureAuthenticationOptions>
    {
        private readonly OAuthAuthorizationServerOptions oauthOptions;

        public SignatureAuthenticationMiddleware(OwinMiddleware next, SignatureAuthenticationOptions options, OAuthAuthorizationServerOptions oauthOptions)
            : base(next, options)
        {
            this.oauthOptions = oauthOptions;
        }

        /// <summary>Creates a handler for validating Basic auth requests.</summary>
        /// <returns>The new handler.</returns>
        protected override AuthenticationHandler<SignatureAuthenticationOptions> CreateHandler()
        {
            return new SignatureAuthenticationHandler(this.Options, this.oauthOptions);
        }
    }
}