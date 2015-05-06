namespace Sentinel.OAuth.Extensions
{
    using Microsoft.Owin;

    using Sentinel.OAuth.Core.Models.OAuth;
    using Sentinel.OAuth.Models.OAuth;

    public static class OwinContextExtensions
    {
        /// <summary>Gets the OAuth context from the current OWIN context</summary>
        /// <param name="context">The OWIN context.</param>
        /// <returns>The OAuth context</returns>
        public static OwinOAuthContext GetOAuthContext(this IOwinContext context)
        {
            return new OwinOAuthContext(context);
        }
    }
}