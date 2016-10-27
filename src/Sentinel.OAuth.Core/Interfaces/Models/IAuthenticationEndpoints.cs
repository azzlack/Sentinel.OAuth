namespace Sentinel.OAuth.Core.Interfaces.Models
{
    public interface IAuthenticationEndpoints
    {
        /// <summary>Gets or sets the authorize endpoint.</summary>
        /// <value>The authorization code endpoint URL.</value>
        string AuthorizationCodeEndpointUrl { get; set; }

        /// <summary>Gets or sets the token endpoint.</summary>
        /// <value>The token endpoint URL.</value>
        string TokenEndpointUrl { get; set; }

        /// <summary>Gets or sets the user information endpoint.</summary>
        /// <value>The identity endpoint URL.</value>
        string IdentityEndpointUrl { get; set; }

        /// <summary>Gets or sets the error endpoint.</summary>
        /// <value>The error endpoint URL.</value>
        string ErrorEndpointUrl { get; set; }

        /// <summary>Gets or sets the login endpoint.</summary>
        /// <value>The login endpoint URL.</value>
        string LoginEndpointUrl { get; set; }

        /// <summary>Gets or sets the logout endpoint.</summary>
        /// <value>The logout endpoint URL.</value>
        string LogoutEndpointUrl { get; set; }

        /// <summary>Gets or sets the refresh endpoint.</summary>
        /// <value>The refresh endpoint URL.</value>
        string RefreshEndpointUrl { get; set; }
    }
}