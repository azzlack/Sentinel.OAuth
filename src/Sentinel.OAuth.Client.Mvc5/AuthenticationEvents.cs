namespace Sentinel.OAuth.Client.Mvc5
{
    using System;
    using System.IO;
    using System.Linq;
    using System.Net;
    using System.Net.Http;
    using System.Security.Claims;
    using System.Threading.Tasks;

    using Microsoft.AspNet.Identity;
    using Microsoft.Owin;
    using Microsoft.Owin.Logging;
    using Microsoft.Owin.Security;

    using Newtonsoft.Json;

    using Sentinel.OAuth.Client.Mvc5.Extensions;
    using Sentinel.OAuth.Client.Mvc5.Framework.Owin;
    using Sentinel.OAuth.Client.Mvc5.Models.Http;
    using Sentinel.OAuth.Core.Models.OAuth.Http;
    using Sentinel.OAuth.Models.Identity;

    public class AuthenticationEvents
    {
        /// <summary>Gets or sets the exception handler.</summary>
        /// <param name="context">The current OWIN context.</param>
        /// <param name="options">The authentication options.</param>
        /// <param name="ex">The exception.</param>
        /// <returns>A Task.</returns>
        public virtual Task OnException(IOwinContext context, SentinelAuthenticationOptions options, Exception ex)
        {
            var query = new QueryBuilder();
            query.Add("error", ex.Message);
            query.Add("error_uri", context.Request.Uri.ToString());

            if (context.Request.IsLocalUrl(options.Endpoints.ErrorEndpointUrl))
            { 
                context.Response.Redirect($"{options.Endpoints.ErrorEndpointUrl}{query}");
            }

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
            var query = new QueryBuilder();
            query.Add("error", errorTitle);
            query.Add("error_description", errorDescription);
            query.Add("error_uri", errorUri);
            
            if (context.Request.IsLocalUrl(options.Endpoints.ErrorEndpointUrl))
            {
                context.Response.Redirect($"{options.Endpoints.ErrorEndpointUrl}{query}");
            }

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
            var query = new QueryBuilder();
            query.Add("error", errorType);
            query.Add("error_uri", context.Request.Uri.ToString());

            if (context.Request.IsLocalUrl(options.Endpoints.ErrorEndpointUrl))
            {
                context.Response.Redirect($"{options.Endpoints.ErrorEndpointUrl}{query}");
            }

            return Task.FromResult<object>(null);
        }

        /// <summary>Gets or sets the token error handler.</summary>
        /// <param name="context">The current OWIN context.</param>
        /// <param name="options">The authentication options.</param>
        /// <param name="tokenResponse">The token response.</param>
        /// <returns>A Task.</returns>
        public virtual Task OnTokenError(IOwinContext context, SentinelAuthenticationOptions options, AccessTokenResponse tokenResponse)
        {
            var query = new QueryBuilder();
            query.Add("error", "invalid_token");
            query.Add("error_uri", context.Request.Uri.ToString());

            if (context.Request.IsLocalUrl(options.Endpoints.ErrorEndpointUrl))
            {
                context.Response.Redirect($"{options.Endpoints.ErrorEndpointUrl}{query}");
            }

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
            var props = new AuthenticationProperties() { RedirectUri = context.Request.Query["ReturnUrl"] };

            context.Authentication.SignOut(props, Constants.DefaultAuthenticationType);
            context.Authentication.SignOut(props, DefaultAuthenticationTypes.ApplicationCookie);

            // Redirect to returnurl if specified, otherwise base url
            if (context.Request.IsLocalUrl(props.RedirectUri))
            {
                context.Response.Redirect(props.RedirectUri);
            }
            else
            {
                context.Response.Redirect("/");
            }

            return Task.FromResult<object>(null);
        }

        /// <summary>Refreshes the token.</summary>
        /// <param name="context">The current OWIN context.</param>
        /// <param name="options">The authentication options.</param>
        /// <returns>A Task.</returns>
        public virtual async Task OnRefresh(IOwinContext context, SentinelAuthenticationOptions options)
        {
            var user = new SentinelPrincipal(context.Authentication.User);

            // Always return json from this endpoint
            context.Response.ContentType = "application/json";

            // Dont refresh if user is authenticated and more than 1 minute remains of its validness
            if (user.Identity.IsAuthenticated && user.ValidTo.Subtract(DateTimeOffset.UtcNow) > TimeSpan.FromMinutes(1))
            {
                return;
            }

            var refreshCookie = context.Request.Cookies.FirstOrDefault(x => x.Key == $"{options.CookieConfiguration.Name}_RT");

            if (refreshCookie.Value != null)
            {
                var refreshTokenResponse = await options.TicketHandler.RefreshTokenAsync(context, options, refreshCookie.Value, options.RedirectUri);

                if (refreshTokenResponse != null)
                {
                    // Sign in as sentinel identity
                    var props = new AuthenticationProperties()
                    {
                        RedirectUri = context.Request.Uri.ToString()
                    };
                    var ticket = await options.TicketHandler.SignInAsync(context, options, refreshTokenResponse, props);

                    await options.Events.OnTokenRefreshed(context, ticket, options);

                    await context.Response.WriteAsync(JsonConvert.SerializeObject(refreshTokenResponse));

                    return;
                }

                options.Logger.WriteError("Refresh token found, but was unable to use it to retrieve a new access token");

                // Delete refresh token if it didnt work
                context.Response.Cookies.Delete($"{options.CookieConfiguration.Name}_RT", new CookieOptions() { Domain = context.Request.Uri.Host });
            }

            context.Response.StatusCode = (int)HttpStatusCode.BadRequest;
            await context.Response.WriteAsync(JsonConvert.SerializeObject(new ErrorResponse("invalid_refresh_token")));
        }

        /// <summary>Handles the error endpoint requests.</summary>
        /// <param name="context">The current OWIN context.</param>
        /// <param name="options">The authentication options.</param>
        /// <returns>A Task.</returns>
        public virtual async Task OnError(IOwinContext context, SentinelAuthenticationOptions options)
        {
            var error = context.Request.Query["error"];
            var errorDescription = context.Request.Query["error_description"];
            var errorUri = context.Request.Query["error_uri"];

            var response = new ErrorResponse(error)
                               {
                                   ErrorDescription = errorDescription,
                                   ErrorUri = errorUri
                               };

            context.Response.ContentType = "application/json";
            await context.Response.WriteAsync(JsonConvert.SerializeObject(response));
        }
    }
}