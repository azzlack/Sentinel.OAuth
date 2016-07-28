namespace Sentinel.OAuth.Client.Mvc5.Framework.Owin
{
    using System;
    using System.Collections.Generic;
    using System.Globalization;
    using System.Net;
    using System.Net.Http;
    using System.Net.Http.Headers;
    using System.Security.Claims;
    using System.Text;
    using System.Threading.Tasks;

    using Microsoft.AspNet.Identity;
    using Microsoft.Owin.Logging;
    using Microsoft.Owin.Security;
    using Microsoft.Owin.Security.Infrastructure;

    using Newtonsoft.Json;

    using Sentinel.OAuth.Client.Mvc5.Models.Http;
    using Sentinel.OAuth.Core.Models.OAuth.Http;
    using Sentinel.OAuth.Core.Models.Tokens;
    using Sentinel.OAuth.Extensions;

    using Constants = Sentinel.OAuth.Client.Mvc5.Constants;

    public class SentinelAuthenticationHandler : AuthenticationHandler<SentinelAuthenticationOptions>
    {
        protected override async Task<AuthenticationTicket> AuthenticateCoreAsync()
        {
            // If already logged in with Sentinel handler, return at once
            if (this.Context.Authentication.User != null && this.Context.Authentication.User.Identity.IsAuthenticated && this.Context.Authentication.User.Identity.AuthenticationType == Constants.DefaultAuthenticationType)
            {
                return new AuthenticationTicket((ClaimsIdentity)this.Context.Authentication.User.Identity, new AuthenticationProperties());
            }

            try
            {
                var query = this.Request.Query;

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

        protected override async Task ApplyResponseChallengeAsync()
        {
            if (this.Response.StatusCode == (int)HttpStatusCode.Unauthorized)
            {
                var challenge = this.Helper.LookupChallenge(this.Options.AuthenticationType, this.Options.AuthenticationMode);

                if (challenge != null)
                {
                    // Set RedirectUri if not set
                    if (string.IsNullOrEmpty(challenge.Properties.RedirectUri))
                    {
                        challenge.Properties.RedirectUri = this.Request.Uri.ToString();
                    }

                    // Set correlation to prevent CSRF
                    this.GenerateCorrelationId(challenge.Properties);

                    this.Response.Redirect(this.BuildChallengeUrl(challenge.Properties, this.Options.RedirectUri));
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

                identity = jwt.ToIdentity(Constants.DefaultAuthenticationType).ToClaimsIdentity();
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