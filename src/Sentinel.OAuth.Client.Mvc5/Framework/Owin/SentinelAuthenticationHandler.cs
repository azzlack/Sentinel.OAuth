namespace Sentinel.OAuth.Client.Mvc5.Framework.Owin
{
    using System;
    using System.Linq;
    using System.Net;
    using System.Security.Principal;
    using System.Text;
    using System.Threading.Tasks;

    using Microsoft.Owin;
    using Microsoft.Owin.Logging;
    using Microsoft.Owin.Security;
    using Microsoft.Owin.Security.Infrastructure;

    using Sentinel.OAuth.Client.Mvc5.Extensions;
    using Sentinel.OAuth.Client.Mvc5.Models.Http;

    public class SentinelAuthenticationHandler : AuthenticationHandler<SentinelAuthenticationOptions>
    {
        /// <summary>
        /// The core authentication logic which must be provided by the handler. Will be invoked at most
        /// once per request. Do not call directly, call the wrapping Authenticate method instead.
        /// </summary>
        /// <returns>The ticket data provided by the authentication logic.</returns>
        protected override async Task<AuthenticationTicket> AuthenticateCoreAsync()
        {
            if (!this.ShouldAuthenticate())
            {
                return null;
            }

            try
            {
                var query = this.Request.Query;

                // Try to refresh token if a cookie exists
                if (this.Context.Authentication.User != null && !this.Context.Authentication.User.Identity.IsAuthenticated)
                {
                    var refreshCookie = this.Context.Request.Cookies.FirstOrDefault(x => x.Key == $"{this.Options.CookieConfiguration.Name}_RT");

                    if (refreshCookie.Value != null)
                    {
                        var refreshTokenResponse = await this.Options.TicketHandler.RefreshTokenAsync(this.Context, this.Options, refreshCookie.Value, this.Options.RedirectUri);

                        if (refreshTokenResponse != null)
                        {
                            // Sign in as sentinel identity
                            var props = new AuthenticationProperties()
                                            {
                                                RedirectUri = this.Context.Request.Uri.ToString()
                                            };
                            var ticket = await this.Options.TicketHandler.SignInAsync(this.Context, this.Options, refreshTokenResponse, props);

                            await this.Options.Events.OnTokenRefreshed(this.Context, ticket, this.Options);

                            return ticket;
                        }

                        this.Options.Logger.WriteError("Refresh token found, but was unable to use it to retrieve a new access token");

                        // Delete refresh token if it didnt work to prevent retries with an invalid token
                        this.Context.Response.Cookies.Delete($"{this.Options.CookieConfiguration.Name}_RT", new CookieOptions() { Domain = this.Request.Uri.Host, Secure = this.Request.IsSecure });
                    }
                }

                // Check for errors
                var error = query["error"];
                if (!string.IsNullOrEmpty(error))
                {
                    var failureMessage = new StringBuilder();
                    failureMessage.Append(error);
                    var errorDescription = query["error_description"];
                    if (!string.IsNullOrEmpty(errorDescription))
                    {
                        failureMessage.Append(";Description=").Append(errorDescription);
                    }
                    var errorUri = query["error_uri"];
                    if (!string.IsNullOrEmpty(errorUri))
                    {
                        failureMessage.Append(";Uri=").Append(errorUri);
                    }

                    this.Options.Logger.WriteError(failureMessage.ToString());

                    await this.Options.Events.OnAuthorizeError(this.Context, this.Options, error, errorDescription, errorUri);

                    return null;
                }

                string code = null;
                string state = null;

                // Parse code
                var codeQueryParam = query.GetValues("code");
                if (codeQueryParam != null && codeQueryParam.Count == 1)
                {
                    code = codeQueryParam[0];
                }

                // Parse state
                var stateQueryParam = query.GetValues("state");
                if (stateQueryParam != null && stateQueryParam.Count == 1)
                {
                    state = stateQueryParam[0];
                }

                // Dont continue if code is null
                if (string.IsNullOrEmpty(code))
                {
                    return null;
                }

                // Extract state
                var properties = this.Options.StateDataFormat.Unprotect(state);

                if (properties == null)
                {
                    await this.Options.Events.OnStateError(this.Context, this.Options, properties, "invalid_state");

                    return null;
                }

                // Validate state to prevent CSRF (See https://tools.ietf.org/html/rfc6749#section-10.12)
                if (!this.ValidateCorrelationId(properties, this.Options.Logger))
                {
                    this.Options.Logger.WriteError("The CSRF Correlation ID is invalid");

                    await this.Options.Events.OnStateError(this.Context, this.Options, properties, "invalid_correlation_id");

                    return null;
                }

                var tokenResponse = await this.Options.TicketHandler.ExchangeCodeAsync(this.Context, this.Options, code, this.Options.RedirectUri);

                if (string.IsNullOrEmpty(tokenResponse.AccessToken))
                {
                    this.Options.Logger.WriteError("No access token was included in the response");

                    await this.Options.Events.OnTokenError(this.Context, this.Options, tokenResponse);

                    return null;
                }

                return await this.Options.TicketHandler.SignInAsync(this.Context, this.Options, tokenResponse, properties);
            }
            catch (Exception ex)
            {
                this.Options.Logger.WriteError("Authentication failed", ex);

                await this.Options.Events.OnException(this.Context, this.Options, ex);

                return null;
            }
        }

        protected override Task ApplyResponseGrantAsync()
        {
            var signin = this.Helper.LookupSignIn(this.Options.AuthenticationType);
            var signout = this.Helper.LookupSignOut(this.Options.AuthenticationType, this.Options.AuthenticationMode);

            if (signin != null)
            {
                // Save access token, refresh token and identity token as cookies
                if (this.Options.CookieConfiguration.SaveTokens)
                {
                    var accessToken = signin.Properties.Dictionary.ContainsKey("access_token") ? signin.Properties.Dictionary["access_token"] : null;
                    var refreshToken = signin.Properties.Dictionary.ContainsKey("refresh_token") ? signin.Properties.Dictionary["refresh_token"] : null;
                    var identityToken = signin.Properties.Dictionary.ContainsKey("id_token") ? signin.Properties.Dictionary["id_token"] : null;

                    if (!string.IsNullOrEmpty(accessToken))
                    {
                        this.Context.Response.Cookies.Append(
                            $"{this.Options.CookieConfiguration.Name}_AT",
                            accessToken,
                            new CookieOptions()
                            {
                                Domain = this.Context.Request.Uri.Host,
                                Expires = signin.Properties.ExpiresUtc?.DateTime,
                                Secure = this.Context.Request.IsSecure
                            });
                    }

                    if (!string.IsNullOrEmpty(refreshToken))
                    {
                        this.Context.Response.Cookies.Append(
                            $"{this.Options.CookieConfiguration.Name}_RT",
                            refreshToken,
                            new CookieOptions()
                            {
                                Domain = this.Context.Request.Uri.Host,
                                Expires = signin.Properties.ExpiresUtc?.DateTime.Add(this.Options.RefreshTokenLifetime),
                                Secure = this.Context.Request.IsSecure
                            });
                    }

                    if (!string.IsNullOrEmpty(identityToken))
                    {
                        this.Context.Response.Cookies.Append(
                            $"{this.Options.CookieConfiguration.Name}_IT",
                            identityToken,
                            new CookieOptions()
                            {
                                Domain = this.Context.Request.Uri.Host,
                                Expires = signin.Properties.ExpiresUtc?.DateTime,
                                Secure = this.Context.Request.IsSecure
                            });
                    }
                }
            }
            else if (signout != null)
            {
                var opts = new CookieOptions() { Domain = this.Request.Uri.Host, Secure = this.Request.IsSecure };

                // Remove cookies from response
                this.Context.Response.Cookies.Delete($"{this.Options.CookieConfiguration.Name}_AT", opts);
                this.Context.Response.Cookies.Delete($"{this.Options.CookieConfiguration.Name}_RT", opts);
                this.Context.Response.Cookies.Delete($"{this.Options.CookieConfiguration.Name}_IT", opts);

                // Set authentication properties to prevent further processing
                this.Context.Authentication.User = new GenericPrincipal(new GenericIdentity("signout"), new []{ "urn:oauth:noauth" });

                return Task.FromResult<object>(null);
            }

            return base.ApplyResponseGrantAsync();
        }

        protected override async Task ApplyResponseChallengeAsync()
        {
            var sentinelChallenge = this.Helper.LookupChallenge(this.Options.AuthenticationType, this.Options.AuthenticationMode);

            if (sentinelChallenge != null)
            {
                if (this.Response.StatusCode == (int)HttpStatusCode.Unauthorized)
                {
                    // Set RedirectUri if not set
                    if (string.IsNullOrEmpty(sentinelChallenge.Properties.RedirectUri))
                    {
                        sentinelChallenge.Properties.RedirectUri = this.Request.Uri.ToString();
                    }

                    // Set correlation to prevent CSRF
                    this.GenerateCorrelationId(sentinelChallenge.Properties);

                    this.Response.Redirect(this.BuildChallengeUrl(sentinelChallenge.Properties, this.Options.RedirectUri));
                }
            }
        }

        /// <summary>Validates that the request should be acted upon.</summary>
        /// <returns>true if it the request should be acted upon, otherwise false.</returns>
        private bool ShouldAuthenticate()
        {
            if (this.Context.Request.IsSameUrl(this.Options.Endpoints.ErrorEndpointUrl))
            {
                return false;
            }

            if (this.Context.Request.IsSameUrl(this.Options.Endpoints.RefreshEndpointUrl))
            {
                return false;
            }

            if (this.Context.Request.IsSameUrl(this.Options.Endpoints.LogoutEndpointUrl))
            {
                return false;
            }

            if (this.Helper.LookupSignOut(this.Options.AuthenticationType, this.Options.AuthenticationMode) != null)
            {
                return false;
            }

            return true;
        }

        private string BuildChallengeUrl(AuthenticationProperties properties, string redirectUri)
        {
            // OAuth2 3.3 space separated
            var scope = string.Join(" ", this.Options.Scope);

            var state = this.Options.StateDataFormat.Protect(properties);

            var queryBuilder = new QueryBuilder()
            {
                { "client_id", this.Options.ClientId },
                { "scope", scope },
                { "response_type", "code" },
                { "redirect_uri", redirectUri ?? string.Empty },
                { "state", state }
            };

            return this.Options.Endpoints.AuthorizationCodeEndpointUrl + queryBuilder;
        }
    }
}