namespace Sentinel.OAuth.Core.Models
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Net;
    using System.Text;

    public class BasicAuthenticationCipher
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="BasicAuthenticationCipher" /> class.
        /// </summary>
        /// <param name="cipher">The cipher. Must be form url encoded.</param>
        public BasicAuthenticationCipher(string cipher)
        {
            var arr = cipher.Split('&');

            if (arr.Length == 0)
            {
                throw new ArgumentException(nameof(cipher), "The cipher is invalid. Are the parameters url encoded?");
            }

            try
            {
                var param = arr.ToDictionary(x => x.Split('=')[0], x => x.Split('=')[1]);

                var clientId = param.ContainsKey("client_id") ? WebUtility.UrlDecode(param["client_id"]) : null;
                var redirectUri = param.ContainsKey("redirect_uri") ? WebUtility.UrlDecode(param["redirect_uri"]) : null;
                var password = param.ContainsKey("password") ? WebUtility.UrlDecode(param["password"]) : null;

                this.ClientId = clientId;
                this.RedirectUri = redirectUri;
                this.Password = password;
            }
            catch (IndexOutOfRangeException ex)
            {
                throw new ArgumentException(nameof(cipher), "The cipher is invalid. It must be on the format 'key=value&key2=value'", ex);
            }
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="BasicAuthenticationCipher" />
        ///  class.
        /// </summary>
        /// <param name="clientId">Identifier for the client.</param>
        /// <param name="redirectUri">URI of the redirect.</param>
        /// <param name="password">The password.</param>
        public BasicAuthenticationCipher(string clientId, string redirectUri, string password)
        {
            this.ClientId = clientId;
            this.RedirectUri = redirectUri;
            this.Password = password;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="BasicAuthenticationCipher" />
        ///  class.
        /// </summary>
        /// <param name="redirectUri">URI of the redirect.</param>
        /// <param name="password">The password.</param>
        public BasicAuthenticationCipher(string redirectUri, string password)
        {
            this.RedirectUri = redirectUri;
            this.Password = password;
        }

        public string ClientId { get; }

        public string RedirectUri { get; }

        public string Password { get; }

        public override string ToString()
        {
            var arr = new List<string>();

            if (!string.IsNullOrEmpty(this.ClientId))
            {
                arr.Add($"client_id={WebUtility.UrlEncode(this.ClientId)}");
            }

            if (!string.IsNullOrEmpty(this.RedirectUri))
            {
                arr.Add($"redirect_uri={WebUtility.UrlEncode(this.RedirectUri)}");
            }

            if (!string.IsNullOrEmpty(this.Password))
            {
                arr.Add($"password={WebUtility.UrlEncode(this.Password)}");
            }

            return string.Join("&", arr);
        }
    }
}