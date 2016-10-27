namespace Sentinel.OAuth.Client.Models
{
    using Sentinel.OAuth.Core.Interfaces.Models;

    public class AuthenticationEndpoints : IAuthenticationEndpoints
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="AuthenticationEndpoints" /> class.
        /// </summary>
        public AuthenticationEndpoints()
        {
            this.AuthorizationCodeEndpointUrl = "/oauth/authorize";
            this.TokenEndpointUrl = "/oauth/token";
            this.IdentityEndpointUrl = "/openid/userinfo";
            this.LoginEndpointUrl = "/sentinel_auth/login";
            this.LogoutEndpointUrl = "/sentinel_auth/logout";
            this.ErrorEndpointUrl = "/sentinel_auth/error";
            this.RefreshEndpointUrl = "/sentinel_auth/refresh";
        }

        /// <summary>Gets or sets the authorize endpoint.</summary>
        /// <value>The authorization code endpoint URL.</value>
        public string AuthorizationCodeEndpointUrl { get; set; }

        /// <summary>Gets or sets the token endpoint.</summary>
        /// <value>The token endpoint URL.</value>
        public string TokenEndpointUrl { get; set; }

        /// <summary>Gets or sets the user information endpoint.</summary>
        /// <value>The identity endpoint URL.</value>
        public string IdentityEndpointUrl { get; set; }

        /// <summary>Gets or sets the error endpoint.</summary>
        /// <value>The error endpoint URL.</value>
        public string ErrorEndpointUrl { get; set; }

        /// <summary>Gets or sets the login endpoint.</summary>
        /// <value>The login endpoint URL.</value>
        public string LoginEndpointUrl { get; set; }

        /// <summary>Gets or sets the logout endpoint.</summary>
        /// <value>The logout endpoint URL.</value>
        public string LogoutEndpointUrl { get; set; }

        /// <summary>Gets or sets the refresh endpoint.</summary>
        /// <value>The refresh endpoint URL.</value>
        public string RefreshEndpointUrl { get; set; }
    }
}