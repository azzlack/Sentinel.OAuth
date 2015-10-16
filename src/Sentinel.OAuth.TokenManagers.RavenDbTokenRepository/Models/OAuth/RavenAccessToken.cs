namespace Sentinel.OAuth.TokenManagers.RavenDbTokenRepository.Models.OAuth
{
    using Core.Interfaces.Models;
    using Sentinel.OAuth.Core.Models.OAuth;
    using System;
    using System.Text;

    public class RavenAccessToken : AccessToken
    {
        /// <summary>
        /// Initializes a new instance of the Sentinel.OAuth.TokenManagers.RavenDbTokenRepository.Models.OAuth.RavenAccessToken class.
        /// </summary>
        public RavenAccessToken()
        {
        }

        /// <summary>
        /// Initializes a new instance of the Sentinel.OAuth.TokenManagers.RavenDbTokenRepository.Models.OAuth.RavenAccessToken class.
        /// </summary>
        /// <param name="token">The access token.</param>
        public RavenAccessToken(IAccessToken token)
            : base(token)
        {
            this.Id = Convert.ToBase64String(Encoding.UTF8.GetBytes(token.ClientId + token.RedirectUri + token.Subject + token.ValidTo.ToString("O")));
            this.Created = DateTime.UtcNow;
        }

        /// <summary>Gets or sets the identifier.</summary>
        /// <value>The identifier.</value>
        public string Id { get; set; }

        /// <summary>
        /// Gets or sets the created date.
        /// </summary>
        /// <value>The created date.</value>
        public DateTime Created { get; set; }
    }
}