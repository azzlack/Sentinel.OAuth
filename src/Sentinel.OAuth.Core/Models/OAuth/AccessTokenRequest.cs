namespace Sentinel.OAuth.Core.Models.OAuth
{
    using System.Collections.Generic;
    using System.Diagnostics;
    using System.Linq;

    using Newtonsoft.Json;
    using Newtonsoft.Json.Linq;

    /// <summary>
    /// Represents an OAuth access token request
    /// </summary>
    [DebuggerDisplay("grant_type: {GrantType}, scope: {Scope}, redirect_uri: {RedirectUri}, username: {Username}")]
    public class AccessTokenRequest
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="AccessTokenRequest"/> class.
        /// </summary>
        public AccessTokenRequest()
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="AccessTokenRequest"/> class.
        /// </summary>
        /// <param name="properties">The properties.</param>
        public AccessTokenRequest(IDictionary<string, string> properties)
        {
            this.GrantType = properties["grant_type"];
            this.Code = properties["code"];
            this.RefreshToken = properties["refresh_token"];
            this.Username = properties["username"];
            this.Password = properties["password"];
            this.Scope = properties["scope"];
            this.RedirectUri = properties["redirect_uri"];
        }

        /// <summary>
        /// Gets or sets the type of the grant.
        /// </summary>
        /// <value>The type of the grant.</value>
        [JsonProperty("grant_type")]
        public string GrantType { get; set; }

        /// <summary>
        /// Gets or sets the code.
        /// </summary>
        /// <value>The code.</value>
        [JsonProperty("code", NullValueHandling = NullValueHandling.Ignore)]
        public string Code { get; set; }

        /// <summary>
        /// Gets or sets the refresh token.
        /// </summary>
        /// <value>The refresh token.</value>
        [JsonProperty("refresh_token", NullValueHandling = NullValueHandling.Ignore)]
        public string RefreshToken { get; set; }

        /// <summary>
        /// Gets or sets the username.
        /// </summary>
        /// <value>The username.</value>
        [JsonProperty("username", NullValueHandling = NullValueHandling.Ignore)]
        public string Username { get; set; }

        /// <summary>
        /// Gets or sets the password.
        /// </summary>
        /// <value>The password.</value>
        [JsonProperty("password", NullValueHandling = NullValueHandling.Ignore)]
        public string Password { get; set; }

        /// <summary>
        /// Gets or sets the scope.
        /// </summary>
        /// <value>The scope.</value>
        [JsonProperty("scope", NullValueHandling = NullValueHandling.Ignore)]
        public string Scope { get; set; }

        /// <summary>
        /// Gets or sets the redirect URI.
        /// </summary>
        /// <value>The redirect URI.</value>
        [JsonProperty("redirect_uri", NullValueHandling = NullValueHandling.Ignore)]
        public string RedirectUri { get; set; }

        /// <summary>
        /// Gets the properties.
        /// </summary>
        /// <value>The properties.</value>
        [JsonIgnore]
        public IEnumerable<KeyValuePair<string, string>> Properties
        {
            get
            {
                var json = JsonConvert.SerializeObject(this);
                var jobject = JObject.Parse(json);

                foreach (var property in jobject)
                {
                    yield return new KeyValuePair<string, string>(property.Key, property.Value != null ? property.Value.ToString() : null);
                }
            }
        }

        /// <summary>
        /// Returns a <see cref="System.String" /> that represents this instance.
        /// </summary>
        /// <returns>A <see cref="System.String" /> that represents this instance.</returns>
        public override string ToString()
        {
            return string.Join(", ", this.Properties.Where(x => x.Value != null).Select(
                x =>
                    {
                        if (x.Key == "api_key" || x.Key == "password")
                        {
                            return string.Format("{0}: {1}", x.Key, "*****");
                        }

                        return string.Format("{0}: {1}", x.Key, x.Value);
                    }));
        }
    }
}