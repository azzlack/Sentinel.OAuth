namespace Sentinel.OAuth.Client.Mvc5
{
    using System;
    using System.Collections.Generic;
    using System.Globalization;
    using System.Net.Http;
    using System.Net.Http.Headers;
    using System.Security.Claims;
    using System.Threading.Tasks;

    using Microsoft.Owin;
    using Microsoft.Owin.Security;

    using Newtonsoft.Json;

    using Sentinel.OAuth.Client.Models;
    using Sentinel.OAuth.Client.Mvc5.Framework.Owin;
    using Sentinel.OAuth.Core.Models.OAuth.Http;
    using Sentinel.OAuth.Core.Models.Tokens;
    using Sentinel.OAuth.Extensions;

    public class TicketHandler
    {
        public virtual async Task<AuthenticationTicket> SignInAsync(IOwinContext context, SentinelAuthenticationOptions options, AccessTokenResponse tokenResponse, AuthenticationProperties properties)
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
                var expiresAt = options.SystemClock.UtcNow + TimeSpan.FromSeconds(tokenResponse.ExpiresIn);

                properties.Dictionary.Add("expires_in", tokenResponse.ExpiresIn.ToString(CultureInfo.InvariantCulture));
                properties.ExpiresUtc = expiresAt;
            }

            await options.Events.OnAuthenticated(context, identity, properties, options);

            // Add authentication response grant so it is accessible in the callback
            context.Authentication.AuthenticationResponseGrant = new AuthenticationResponseGrant(identity, properties);

            return new AuthenticationTicket(identity, properties);
        }

        public virtual async Task<AccessTokenResponse> RefreshTokenAsync(IOwinContext context, SentinelAuthenticationOptions options, string refreshToken, string redirectUri)
        {
            // Build up the body for the token request
            var tokenRequestParameters = new Dictionary<string, string>
                                             {
                                                 { "grant_type", "refresh_token" },
                                                 { "refresh_token", refreshToken },
                                                 { "redirect_uri", redirectUri }
                                             };

            var requestContent = new FormUrlEncodedContent(tokenRequestParameters);

            var requestMessage = new HttpRequestMessage(HttpMethod.Post, options.Endpoints.TokenEndpointUrl);
            requestMessage.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            requestMessage.Headers.Authorization = new BasicAuthenticationHeaderValue(options.ClientId, options.ClientSecret);
            requestMessage.Content = requestContent;
            var response = await options.Backchannel.SendAsync(requestMessage);

            if (response.IsSuccessStatusCode)
            {
                return JsonConvert.DeserializeObject<AccessTokenResponse>(await response.Content.ReadAsStringAsync());
            }

            return null;
        }

        public virtual async Task<AccessTokenResponse> ExchangeCodeAsync(IOwinContext context, SentinelAuthenticationOptions options, string code, string redirectUri)
        {
            // Build up the body for the token request
            var tokenRequestParameters = new Dictionary<string, string>
                                             {
                                                 { "grant_type", "authorization_code" },
                                                 { "code", code },
                                                 { "redirect_uri", redirectUri },
                                                 { "client_id", options.ClientId },
                                                 { "client_secret", options.ClientSecret }
                                             };

            var requestContent = new FormUrlEncodedContent(tokenRequestParameters);

            var requestMessage = new HttpRequestMessage(HttpMethod.Post, options.Endpoints.TokenEndpointUrl);
            requestMessage.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            requestMessage.Content = requestContent;
            var response = await options.Backchannel.SendAsync(requestMessage);

            if (response.IsSuccessStatusCode)
            {
                return JsonConvert.DeserializeObject<AccessTokenResponse>(await response.Content.ReadAsStringAsync());
            }

            return null;
        }
    }
}