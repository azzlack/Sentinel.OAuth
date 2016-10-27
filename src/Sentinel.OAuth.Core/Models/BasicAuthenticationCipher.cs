namespace Sentinel.OAuth.Core.Models
{
    using System.Linq;
    using System.Net;

    public class BasicAuthenticationCipher
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="BasicAuthenticationCipher" /> class.
        /// </summary>
        /// <param name="cipher">The cipher. Must be form url encoded.</param>
        public BasicAuthenticationCipher(string cipher)
        {
            var param = cipher.Split('&').ToDictionary(x => x.Split('=')[0], x => x.Split('=')[1]);

            var clientId = param.ContainsKey("client_id") ? WebUtility.UrlDecode(param["client_id"]) : null;
            var redirectUri = param.ContainsKey("redirect_uri") ? WebUtility.UrlDecode(param["redirect_uri"]) : null;
            var password = param.ContainsKey("password") ? WebUtility.UrlDecode(param["password"]) : null;

            this.ClientId = clientId;
            this.RedirectUri = redirectUri;
            this.Password = password;
        }

        public BasicAuthenticationCipher(string clientId, string redirectUri, string password)
        {
            this.ClientId = clientId;
            this.RedirectUri = redirectUri;
            this.Password = password;
        }

        public string ClientId { get; }

        public string RedirectUri { get; }

        public string Password { get; }

        public override string ToString()
        {
            return $"client_id={WebUtility.UrlEncode(this.ClientId)}&redirect_uri={WebUtility.UrlEncode(this.RedirectUri)}&password={WebUtility.UrlEncode(this.Password)}";
        }
    }
}