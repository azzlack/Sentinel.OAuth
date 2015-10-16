namespace Sentinel.OAuth.TokenManagers.RavenDbTokenRepository.Models.OAuth
{
    using Sentinel.OAuth.Core.Interfaces.Models;
    using Sentinel.OAuth.Core.Models.OAuth;
    using System;
    using System.Text;

    public class RavenAuthorizationCode : AuthorizationCode
    {
        /// <summary>
        /// Initializes a new instance of the Sentinel.OAuth.TokenManagers.RavenDbTokenRepository.Models.OAuth.RavenAuthorizationCode class.
        /// </summary>
        public RavenAuthorizationCode()
        {
        }

        /// <summary>
        /// Initializes a new instance of the Sentinel.OAuth.TokenManagers.RavenDbTokenRepository.Models.OAuth.RavenAuthorizationCode class.
        /// </summary>
        /// <param name="authorizationCode">The authorization code.</param>
        public RavenAuthorizationCode(IAuthorizationCode authorizationCode)
            : base(authorizationCode)
        {
            this.Id = Convert.ToBase64String(Encoding.UTF8.GetBytes(authorizationCode.ClientId + authorizationCode.RedirectUri + authorizationCode.Subject + authorizationCode.ValidTo.ToString("O")));
            this.Created = DateTime.UtcNow;
        }

        /// <summary>Gets or sets the identifier.</summary>
        /// <value>The identifier.</value>
        public string Id { get; set; }

        /// <summary>Gets or sets the created date.</summary>
        /// <value>The created date.</value>
        public DateTime Created { get; set; }
    }
}