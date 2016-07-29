namespace Sentinel.OAuth.Middleware
{
    using Microsoft.Owin;
    using Microsoft.Owin.Security.Infrastructure;

    public class ApiKeyAuthenticationMiddleware : AuthenticationMiddleware<ApiKeyAuthenticationOptions>
    {
        /// <summary>Initializes a new instance of the <see cref="ApiKeyAuthenticationMiddleware" /> class.</summary>
        /// <param name="next">The next.</param>
        /// <param name="options">Options for controlling the operation.</param>
        public ApiKeyAuthenticationMiddleware(OwinMiddleware next, ApiKeyAuthenticationOptions options)
            : base(next, options)
        {
        }

        /// <summary>Creates a handler for validating Basic auth requests.</summary>
        /// <returns>The new handler.</returns>
        protected override AuthenticationHandler<ApiKeyAuthenticationOptions> CreateHandler()
        {
            return new ApiKeyAuthenticationHandler(this.Options);
        }
    }
}