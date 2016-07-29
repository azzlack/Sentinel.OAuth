namespace Sentinel.OAuth.Client.Mvc5.Framework.Owin
{
    using System;
    using System.Collections.Generic;
    using System.Globalization;
    using System.Linq;
    using System.Net;
    using System.Net.Http;
    using System.Net.Http.Headers;
    using System.Security.Claims;
    using System.Text;
    using System.Threading.Tasks;

    using Microsoft.AspNet.Identity;
    using Microsoft.Owin;
    using Microsoft.Owin.Logging;
    using Microsoft.Owin.Security;
    using Microsoft.Owin.Security.Infrastructure;

    using Newtonsoft.Json;

    using Sentinel.OAuth.Client.Mvc5.Models.Http;
    using Sentinel.OAuth.Core.Models.OAuth.Http;
    using Sentinel.OAuth.Core.Models.Tokens;
    using Sentinel.OAuth.Extensions;

    public class SentinelAuthenticationHandler : AuthenticationHandler<SentinelAuthenticationOptions>
    {
        protected override async Task<AuthenticationTicket> AuthenticateCoreAsync()
        {
            try
            {
                var query = this.Request.Query;

                // Try to refresh token if a cookie exists
                if (this.Context.Authentication.User != null && !this.Context.Authentication.User.Identity.IsAuthenticated)
                {
                    var refreshCookie = this.Context.Request.Cookies.FirstOrDefault(x => x.Key == $"{this.Options.CookieConfiguration.Name}_RT");

                    if (refreshCookie.Value != null)
                    {
                        var refreshTokenResponse = await this.RefreshTokenAsync(refreshCookie.Value, this.Options.RedirectUri);

                        if (refreshTokenResponse != null)
                        {
                            // Sign in as sentinel identity
                            var props = new AuthenticationProperties()
                                            {
                                                RedirectUri = this.Context.Request.Uri.ToString()
                                            };
                            var ticket = await this.SignInAsync(refreshTokenResponse, props);

                            await this.Options.Events.OnTokenRefreshed(this.Context, ticket, this.Options);

                            return ticket;
                        }

                        this.Options.Logger.WriteError("Refresh token found, but was unable to use it to retrieve a new access token");

                        // Delete refresh token if it didnt work
                        this.Context.Response.Cookies.Delete($"{this.Options.CookieConfiguration.Name}_RT");
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

                var tokenResponse = await this.ExchangeCodeAsync(code, this.Options.RedirectUri);

                if (string.IsNullOrEmpty(tokenResponse.AccessToken))
                {
                    this.Options.Logger.WriteError("No access token was included in the response");

                    await this.Options.Events.OnTokenError(this.Context, this.Options, tokenResponse);

                    return null;
                }

                return await this.SignInAsync(tokenResponse, properties);
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
                                Expires = signin.Properties.ExpiresUtc?.DateTime,
                                Secure = this.Context.Request.IsSecure
                            });
                    }
                }
            }
            else if (signout != null)
            {
                // Remove cookies
                this.Context.Response.Cookies.Delete($"{this.Options.CookieConfiguration.Name}_AT");
                this.Context.Response.Cookies.Delete($"{this.Options.CookieConfiguration.Name}_RT");
                this.Context.Response.Cookies.Delete($"{this.Options.CookieConfiguration.Name}_IT");
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

        protected virtual async Task<AuthenticationTicket> SignInAsync(AccessTokenResponse tokenResponse, AuthenticationProperties properties)
        {
            // Get user identity
            var identity = new ClaimsIdentity();

            if (!string.IsNullOrEmpty(tokenResponse.IdToken))
            {
                var jwt = new JsonWebToken(tokenResponse.IdToken);

                identity = jwt.ToIdentity(Mvc5.Constants.DefaultAuthenticationType).ToClaimsIdentity();
            }
            else
            {
                // TODO: Get user by making a request to the userinfo endpoint
            }

            // Add tokens to ticket
            properties.Dictionary.Add("access_token", tokenResponse.AccessToken);

            if (!string.IsNullOrEmpty(tokenResponse.RefreshToken))
            {
                properties.Dictionary.Add("refresh_token", tokenResponse.RefreshToken);
            }

            if (!string.IsNullOrEmpty(tokenResponse.IdToken))
            {
                properties.Dictionary.Add("id_token", tokenResponse.IdToken);
            }

            if (!string.IsNullOrEmpty(tokenResponse.TokenType))
            {
                properties.Dictionary.Add("token_type", tokenResponse.TokenType);
            }

            if (tokenResponse.ExpiresIn > 0)
            {
                var expiresAt = this.Options.SystemClock.UtcNow + TimeSpan.FromSeconds(tokenResponse.ExpiresIn);

                properties.Dictionary.Add("expires_in", tokenResponse.ExpiresIn.ToString(CultureInfo.InvariantCulture));
                properties.ExpiresUtc = expiresAt;
            }

            await this.Options.Events.OnAuthenticated(this.Context, identity, properties, this.Options);

            // Add authentication response grant so it is accessible in the callback
            this.Context.Authentication.AuthenticationResponseGrant = new AuthenticationResponseGrant(identity, properties);

            return new AuthenticationTicket(identity, properties);
        }

        protected virtual async Task<AccessTokenResponse> RefreshTokenAsync(string refreshToken, string redirectUri)
        {
            // Build up the body for the token request
            var tokenRequestParameters = new Dictionary<string, string>
                                             {
                                                 { "grant_type", "refresh_token" },
                                                 { "refresh_token", refreshToken },
                                                 { "redirect_uri", redirectUri }
                                             };

            var requestContent = new FormUrlEncodedContent(tokenRequestParameters);

            var requestMessage = new HttpRequestMessage(HttpMethod.Post, this.Options.Endpoints.TokenEndpointUrl);
            requestMessage.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            requestMessage.Headers.Authorization = new BasicAuthenticationHeaderValue(this.Options.ClientId, this.Options.ClientSecret);
            requestMessage.Content = requestContent;
            var response = await this.Options.Backchannel.SendAsync(requestMessage);

            if (response.IsSuccessStatusCode)
            {
                return JsonConvert.DeserializeObject<AccessTokenResponse>(await response.Content.ReadAsStringAsync());
            }

            return null;
        }

        protected virtual async Task<AccessTokenResponse> ExchangeCodeAsync(string code, string redirectUri)
        {
            // Build up the body for the token request
            var tokenRequestParameters = new Dictionary<string, string>
                                             {
                                                 { "grant_type", "authorization_code" },
                                                 { "code", code },
                                                 { "redirect_uri", redirectUri },
                                                 { "client_id", this.Options.ClientId },
                                                 { "client_secret", this.Options.ClientSecret }
                                             };

            var requestContent = new FormUrlEncodedContent(tokenRequestParameters);

            var requestMessage = new HttpRequestMessage(HttpMethod.Post, this.Options.Endpoints.TokenEndpointUrl);
            requestMessage.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            requestMessage.Content = requestContent;
            var response = await this.Options.Backchannel.SendAsync(requestMessage);

            if (response.IsSuccessStatusCode)
            {
                return JsonConvert.DeserializeObject<AccessTokenResponse>(await response.Content.ReadAsStringAsync());
            }

            return null;
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