namespace Sentinel.OAuth.Client.Mvc5
{
    using System;
    using System.Linq;
    using System.Security.Claims;
    using System.Threading.Tasks;

    using Microsoft.AspNet.Identity;
    using Microsoft.Owin;
    using Microsoft.Owin.Security;

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

                // Save access token, refresh token and identity token as cookies
                if (options.CookieConfiguration.SaveTokens)
                {
                    var accessToken = props.Dictionary.ContainsKey("access_token") ? props.Dictionary["access_token"] : null;
                    var refreshToken = props.Dictionary.ContainsKey("refresh_token") ? props.Dictionary["refresh_token"] : null;
                    var identityToken = props.Dictionary.ContainsKey("id_token") ? props.Dictionary["id_token"] : null;

                    if (!string.IsNullOrEmpty(accessToken))
                    {
                        context.Response.Cookies.Append(
                            $"{options.CookieConfiguration.Name}_AT",
                            accessToken,
                            new CookieOptions()
                            {
                                Expires = props.ExpiresUtc?.DateTime,
                                Secure = context.Request.IsSecure
                            });
                    }

                    if (!string.IsNullOrEmpty(refreshToken))
                    {
                        context.Response.Cookies.Append(
                            $"{options.CookieConfiguration.Name}_RT",
                            refreshToken,
                            new CookieOptions()
                            {
                                Expires = props.ExpiresUtc?.DateTime.Add(options.RefreshTokenLifetime),
                                Secure = context.Request.IsSecure
                            });
                    }

                    if (!string.IsNullOrEmpty(identityToken))
                    {
                        context.Response.Cookies.Append(
                            $"{options.CookieConfiguration.Name}_IT",
                            identityToken,
                            new CookieOptions()
                            {
                                Expires = props.ExpiresUtc?.DateTime,
                                Secure = context.Request.IsSecure
                            });
                    }
                }

                // Redirect to returnurl if valid
                if (!string.IsNullOrEmpty(props.RedirectUri))
                {
                    var host = new Uri(context.Request.Uri.GetLeftPart(UriPartial.Authority));
                    var returnUrl = new Uri(props.RedirectUri);

                    if (!returnUrl.IsAbsoluteUri || host.IsBaseOf(returnUrl))
                    {
                        context.Response.Redirect(returnUrl.ToString());
                    }
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
            // TODO: Last minute claims changes

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

            context.Response.Redirect("/");

            return Task.FromResult<object>(null);
        }
    }
}