namespace Sentinel.OAuth.Client.Mvc5
{
    public class AuthenticationEndpoints
    {
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
    }
}