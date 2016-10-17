namespace Sentinel.OAuth.Middleware
{
    using Microsoft.Owin;
    using Microsoft.Owin.Security.Infrastructure;

    public class SignatureAuthenticationMiddleware : AuthenticationMiddleware<SignatureAuthenticationOptions>
    {
        /// <summary>Initializes a new instance of the <see cref="SignatureAuthenticationMiddleware" /> class.</summary>
        /// <param name="next">The next.</param>
        /// <param name="options">Options for controlling the operation.</param>
        public SignatureAuthenticationMiddleware(OwinMiddleware next, SignatureAuthenticationOptions options)
            : base(next, options)
        {
        }

        /// <summary>Creates a handler for validating Basic auth requests.</summary>
        /// <returns>The new handler.</returns>
        protected override AuthenticationHandler<SignatureAuthenticationOptions> CreateHandler()
        {
            return new SignatureAuthenticationHandler(this.Options);
        }
    }
}