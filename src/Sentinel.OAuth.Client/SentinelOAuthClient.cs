namespace Sentinel.OAuth.Client
{
    using Newtonsoft.Json;
    using Sentinel.OAuth.Client.Interfaces;
    using Sentinel.OAuth.Core.Models.OAuth.Http;
    using System;
    using System.Net;
    using System.Net.Http;
    using System.Net.Http.Headers;
    using System.Security;
    using System.Text;
    using System.Threading.Tasks;

    /// <summary>OAuth client for Sentinel.</summary>
    public class SentinelOAuthClient : IOAuthClient, IDisposable
    {
        /// <summary>
        /// The cookie container
        /// </summary>
        private readonly CookieContainer cookieContainer;

        /// <summary>
        /// The http handler
        /// </summary>
        private readonly HttpMessageHandler handler;

        /// <summary>
        ///     Initializes a new instance of the Sentinel.OAuth.Client.SentinelOAuthClient class.
        /// </summary>
        /// <param name="settings">Options for controlling the operation.</param>
        public SentinelOAuthClient(ISentinelClientSettings settings)
        {
            this.Settings = settings;

            this.cookieContainer = new CookieContainer();

            var handler = new HttpClientHandler()
            {
                CookieContainer = this.cookieContainer,
                UseCookies = true,
                AllowAutoRedirect = false
            };

            if (handler.SupportsAutomaticDecompression)
            {
                handler.AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate;
            }

            this.handler = handler;

            this.Client = new HttpClient(this.handler) { BaseAddress = settings.Url };
        }

        /// <summary>Initializes a new instance of the Sentinel.OAuth.Client.SentinelOAuthClient class.</summary>
        /// <param name="settings">Options for controlling the operation.</param>
        /// <param name="handler">The http handler.</param>
        public SentinelOAuthClient(ISentinelClientSettings settings, HttpMessageHandler handler)
        {
            this.Settings = settings;

            this.handler = handler;

            this.Client = new HttpClient(this.handler) { BaseAddress = settings.Url };
        }

        /// <summary>
        /// Gets the http client
        /// </summary>
        public HttpClient Client { get; }

        /// <summary>Gets the settings.</summary>
        /// <value>The settings.</value>
        public ISentinelClientSettings Settings { get; }

        /// <summary>Authenticates the current client and returns an access token.</summary>
        /// <exception cref="Exception">Thrown when an exception error condition occurs.</exception>
        /// <returns>The access token.</returns>
        public virtual async Task<AccessTokenResponse> Authenticate()
        {
            // Get access token. 
            var accessTokenRequest = new AccessTokenRequest()
            {
                Scope = this.Settings.RedirectUri,
                GrantType = "client_credentials"
            };

            var request = new HttpRequestMessage(HttpMethod.Post, "oauth/token")
            {
                Content = new FormUrlEncodedContent(accessTokenRequest.Properties)
            };
            request.Headers.Authorization = new BasicAuthenticationHeaderValue(this.Settings.ClientId, this.Settings.ClientSecret);

            var response = await this.Client.SendAsync(request).ConfigureAwait(false);

            if (response.IsSuccessStatusCode)
            {
                return JsonConvert.DeserializeObject<AccessTokenResponse>(
                    await response.Content.ReadAsStringAsync());
            }

            throw new SecurityException(
                $"Unable to get access token for application {{ {accessTokenRequest} }}.\r\n",
                new HttpRequestException(await response.Content.ReadAsStringAsync()));
        }

        /// <summary>Authenticates the specified user and client and returns an access token.</summary>
        /// <exception cref="Exception">Thrown when an exception error condition occurs.</exception>
        /// <param name="userName">The username.</param>
        /// <param name="password">The password.</param>
        /// <returns>The access token.</returns>
        public virtual async Task<AccessTokenResponse> Authenticate(string userName, string password)
        {
            // Get access token
            var accessTokenRequest = new AccessTokenRequest()
            {
                Username = userName,
                Password = password,
                RedirectUri = this.Settings.RedirectUri,
                GrantType = "password"
            };

            var accessTokenRequestMessage = new HttpRequestMessage(HttpMethod.Post, "oauth/token")
            {
                Content = new FormUrlEncodedContent(accessTokenRequest.Properties)
            };
            accessTokenRequestMessage.Headers.Authorization = new BasicAuthenticationHeaderValue(this.Settings.ClientId, this.Settings.ClientSecret);

            var accessTokenResponseMessage = await this.Client.SendAsync(accessTokenRequestMessage).ConfigureAwait(false);

            if (accessTokenResponseMessage.IsSuccessStatusCode)
            {
                var accessTokenResponse = JsonConvert.DeserializeObject<AccessTokenResponse>(await accessTokenResponseMessage.Content.ReadAsStringAsync());

                return accessTokenResponse;
            }

            throw new SecurityException($"Unable to get access token for user {{ {accessTokenRequestMessage} }}.\r\n", new HttpRequestException(await accessTokenResponseMessage.Content.ReadAsStringAsync()));
        }

        /// <summary>Re-authenticates by refreshing the access token.</summary>
        /// <exception cref="Exception">Thrown when an exception error condition occurs.</exception>
        /// <param name="refreshToken">The refresh token.</param>
        /// <returns>The access token.</returns>
        public virtual async Task<AccessTokenResponse> RefreshAuthentication(string refreshToken)
        {
            // Get access token
            var accessTokenRequest = new AccessTokenRequest()
            {
                RefreshToken = refreshToken,
                RedirectUri = this.Settings.RedirectUri,
                GrantType = "refresh_token"
            };

            var request = new HttpRequestMessage(HttpMethod.Post, "oauth/token")
            {
                Content = new FormUrlEncodedContent(accessTokenRequest.Properties)
            };
            request.Headers.Authorization = new AuthenticationHeaderValue(
                "Basic",
                Convert.ToBase64String(
                    Encoding.UTF8.GetBytes(string.Format("{0}:{1}", this.Settings.ClientId, this.Settings.ClientSecret))));

            var response = await this.Client.SendAsync(request).ConfigureAwait(false);

            if (response.IsSuccessStatusCode)
            {
                return JsonConvert.DeserializeObject<AccessTokenResponse>(await response.Content.ReadAsStringAsync());
            }

            throw new SecurityException("Unable to refresh access token", new HttpRequestException(await response.Content.ReadAsStringAsync()));
        }

        /// <summary>Gets the identity.</summary>
        /// <param name="token">The token.</param>
        /// <returns>The identity.</returns>
        public async Task<IdentityResponse> GetIdentity(string token)
        {
            var request = new HttpRequestMessage(HttpMethod.Get, "openid/identity");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

            var response = await this.Client.SendAsync(request).ConfigureAwait(false);

            if (response.IsSuccessStatusCode)
            {
                return JsonConvert.DeserializeObject<IdentityResponse>(await response.Content.ReadAsStringAsync());
            }

            throw new SecurityException(
                $"Unable to get identity.\r\n",
                new HttpRequestException(await response.Content.ReadAsStringAsync()));
        }

        /// <summary>Gets the cookies.</summary>
        /// <returns>A list of cookies.</returns>
        public virtual async Task<CookieCollection> GetCookies()
        {
            return this.cookieContainer?.GetCookies(this.Client.BaseAddress);
        }

        /// <summary>Performs application-defined tasks associated with freeing, releasing, or resetting unmanaged resources.</summary>
        public virtual void Dispose()
        {
            this.Client.Dispose();
        }
    }
}