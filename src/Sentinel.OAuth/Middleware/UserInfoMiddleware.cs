namespace Sentinel.OAuth.Middleware
{
    using Microsoft.Owin;
    using Newtonsoft.Json;
    using Sentinel.OAuth.Core.Constants.OAuth;
    using Sentinel.OAuth.Core.Models.OAuth.Http;
    using Sentinel.OAuth.Extensions;
    using Sentinel.OAuth.Models.Identity;
    using System.Net;
    using System.Threading.Tasks;

    public class UserInfoMiddleware : OwinMiddleware
    {
        /// <summary>
        /// Instantiates the middleware with an optional pointer to the next component.
        /// </summary>
        /// <param name="next">The next component.</param>
        public UserInfoMiddleware(OwinMiddleware next)
            : base(next)
        {
        }

        /// <summary>Process an individual request.</summary>
        /// <param name="context">The context.</param>
        /// <returns>A Task.</returns>
        public override async Task Invoke(IOwinContext context)
        {
            if (context.Authentication.User != null && context.Authentication.User.Identity.IsAuthenticated)
            {
                context.Response.ContentType = "application/json";
                var identity = new SentinelIdentity(context.Authentication.User.Identity);
                await context.Response.WriteAsync(JsonConvert.SerializeObject(identity.AsIdentityResponse()));
            }
            else
            {
                context.Response.StatusCode = (int)HttpStatusCode.Unauthorized;
                context.Response.ContentType = "application/json";
                context.Response.Headers["WWW-Authenticate"] = string.Empty;
                await context.Response.WriteAsync(JsonConvert.SerializeObject(new ErrorResponse(ErrorCode.InvalidToken)));
            }
        }
    }
}