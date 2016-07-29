namespace Sentinel.OAuth.Client.Mvc5
{
    using System;
    using System.Linq;
    using System.Security.Claims;
    using System.Threading.Tasks;

    using Microsoft.AspNet.Identity;
    using Microsoft.Owin;
    using Microsoft.Owin.Security;

    using Sentinel.OAuth.Client.Mvc5.Extensions;
    using Sentinel.OAuth.Client.Mvc5.Framework.Owin;
    using Sentinel.OAuth.Core.Models.OAuth.Http;

    public class AuthenticationEvents
    {
        /// <summary>Gets or sets the exception handler.</summary>
        /// <param name="context">The current OWIN context.</param>
        /// <param name="options">The authentication options.</param>
        /// <param name="ex">The exception.</param>
        /// <returns>A Task.</returns>
        public virtual Task OnException(IOwinContext context, SentinelAuthenticationOptions options, Exception ex)
        {
            // TODO: Redirect to error endpoint with the error as query parameters. 

            return Task.FromResult<object>(null);
        }

        /// <summary>Gets or sets the authorize error handler.</summary>
        /// <param name="context">The current OWIN context.</param>
        /// <param name="options">The authentication options.</param>
        /// <param name="errorTitle">The error title.</param>
        /// <param name="errorDescription">The error description.</param>
        /// <param name="errorUri">The error URI.</param>
        /// <returns>A Task.</returns>
        public virtual Task OnAuthorizeError(IOwinContext context, SentinelAuthenticationOptions options, string errorTitle, string errorDescription, string errorUri)
        {
            // TODO: Redirect to error endpoint with the error as query parameters

            return Task.FromResult<object>(null);
        }

        /// <summary>Executes the token refreshed action.</summary>
        /// <param name="context">The current OWIN context.</param>
        /// <param name="ticket">The ticket.</param>
        /// <param name="options">The authentication options.</param>
        /// <returns>A Task.</returns>
        public virtual async Task OnTokenRefreshed(IOwinContext context, AuthenticationTicket ticket, SentinelAuthenticationOptions options)
        {
            // Login with cookie identity at once
            var cookieIdentity = new ClaimsIdentity(ticket.Identity.Claims, DefaultAuthenticationTypes.ApplicationCookie);

            // Persist cookie if it has an expire date
            if (ticket.Properties.ExpiresUtc != null)
            {
                ticket.Properties.IsPersistent = true;
            }

            context.Authentication.SignIn(ticket.Properties, cookieIdentity);
        }

        /// <summary>Executes the authorize callback action.</summary>
        /// <param name="context">The current OWIN context.</param>
        /// <param name="options">The authentication options.</param>
        /// <returns>A Task.</returns>
        public virtual async Task OnAuthorizeCallback(IOwinContext context, SentinelAuthenticationOptions options)
        {
            if (context.Authentication.User != null && context.Authentication.User.Identity.IsAuthenticated)
            {
                var sentinelIdentity = context.Authentication.User.Identities.FirstOrDefault(x => x.AuthenticationType == Constants.DefaultAuthenticationType);
                
                if (sentinelIdentity == null)
                {
                    return;
                }

                var props = options.StateDataFormat.Unprotect(context.Request.Query["state"]);

                if (context.Authentication.AuthenticationResponseGrant != null)
                {
                    props = context.Authentication.AuthenticationResponseGrant.Properties;
                }

                var cookieIdentity = new ClaimsIdentity(sentinelIdentity.Claims, DefaultAuthenticationTypes.ApplicationCookie);

                // Persist cookie if it has an expire date
                if (props.ExpiresUtc != null)
                {
                    props.IsPersistent = true;
                }

                context.Authentication.SignIn(props, cookieIdentity);

                // Redirect to returnurl if valid
                if (context.Request.IsLocalUrl(props.RedirectUri))
                {
                    context.Response.Redirect(props.RedirectUri);
                }
                else
                {
                    context.Response.Redirect("/");
                }
            }
        }

        /// <summary>Gets or sets the authorize error handler.</summary>
        /// <param name="context">The current OWIN context.</param>
        /// <param name="options">The authentication options.</param>
        /// <param name="properties">The authentication properties.</param>
        /// <param name="errorType">Type of the error.</param>
        /// <returns>A Task.</returns>
        public virtual Task OnStateError(IOwinContext context, SentinelAuthenticationOptions options, AuthenticationProperties properties, string errorType)
        {
            // TODO: Redirect to error endpoint with the error as query parameters

            return Task.FromResult<object>(null);
        }

        /// <summary>Gets or sets the code error handler.</summary>
        /// <param name="context">The current OWIN context.</param>
        /// <param name="options">The authentication options.</param>
        /// <param name="code">The code.</param>
        /// <returns>A Task.</returns>
        public virtual Task OnCodeError(IOwinContext context, SentinelAuthenticationOptions options, string code)
        {
            // TODO: Redirect to error endpoint with the error as query parameters

            return Task.FromResult<object>(null);
        }

        /// <summary>Gets or sets the token error handler.</summary>
        /// <param name="context">The current OWIN context.</param>
        /// <param name="options">The authentication options.</param>
        /// <param name="tokenResponse">The token response.</param>
        /// <returns>A Task.</returns>
        public virtual Task OnTokenError(IOwinContext context, SentinelAuthenticationOptions options, AccessTokenResponse tokenResponse)
        {
            // TODO: Redirect to error endpoint with the error as query parameters. 

            return Task.FromResult<object>(null);
        }

        /// <summary>Gets or sets the authenticated handler.</summary>
        /// <param name="context">The current OWIN context.</param>
        /// <param name="identity">The identity.</param>
        /// <param name="properties">The authentication properties.</param>
        /// <param name="options">The authentication options.</param>
        /// <returns>A Task.</returns>
        public virtual Task OnAuthenticated(IOwinContext context, ClaimsIdentity identity, AuthenticationProperties properties, SentinelAuthenticationOptions options)
        {
            if (properties.Dictionary.ContainsKey("access_token") && !identity.HasClaim(x => x.Type == "access_token"))
            {
                identity.AddClaim(new Claim("access_token", properties.Dictionary["access_token"]));
            }

            if (properties.Dictionary.ContainsKey("refresh_token") && !identity.HasClaim(x => x.Type == "refresh_token"))
            {
                identity.AddClaim(new Claim("refresh_token", properties.Dictionary["refresh_token"]));
            }

            return Task.FromResult<object>(null);
        }

        /// <summary>Gets or sets the sign in handler.</summary>
        /// <param name="context">The current OWIN context.</param>
        /// <param name="options">The authentication options.</param>
        /// <returns>A Task.</returns>
        public virtual Task OnSignIn(IOwinContext context, SentinelAuthenticationOptions options)
        {
            context.Authentication.Challenge(
                       new AuthenticationProperties() { RedirectUri = options.RedirectUri },
                       Constants.DefaultAuthenticationType);

            return Task.FromResult<object>(null);
        }

        /// <summary>Gets or sets the sign out handler.</summary>
        /// <param name="context">The current OWIN context.</param>
        /// <param name="options">The authentication options.</param>
        /// <returns>A Task.</returns>
        public virtual Task OnSignOut(IOwinContext context, SentinelAuthenticationOptions options)
        {
            context.Authentication.SignOut(Constants.DefaultAuthenticationType);
            context.Authentication.SignOut(DefaultAuthenticationTypes.ApplicationCookie);

            var returnUrl = context.Request.Query["ReturnUrl"];

            if (!string.IsNullOrEmpty(returnUrl) && context.Request.IsLocalUrl(returnUrl))
            {
                context.Response.Redirect(returnUrl);
            }
            else
            {
                context.Response.Redirect("/");
            }

            return Task.FromResult<object>(null);
        }
    }
}