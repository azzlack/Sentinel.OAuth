namespace Sentinel.OAuth.Middleware
{
    using Microsoft.Owin;
    using Microsoft.Owin.Security.Infrastructure;

    public class BasicAuthenticationMiddleware : AuthenticationMiddleware<BasicAuthenticationOptions>
    {
        /// <summary>Initializes a new instance of the <see cref="BasicAuthenticationMiddleware" /> class.</summary>
        /// <param name="next">The next.</param>
        /// <param name="options">Options for controlling the operation.</param>
        public BasicAuthenticationMiddleware(OwinMiddleware next, BasicAuthenticationOptions options)
            : base(next, options)
        {
        }

        /// <summary>Creates a handler for validating Basic auth requests.</summary>
        /// <returns>The new handler.</returns>
        protected override AuthenticationHandler<BasicAuthenticationOptions> CreateHandler()
        {
            return new BasicAuthenticationHandler(this.Options);
        }
    }
}