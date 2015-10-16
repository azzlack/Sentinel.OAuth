namespace Sentinel.OAuth.TokenManagers.RavenDbTokenRepository.Models.OAuth
{
    using Sentinel.OAuth.Core.Interfaces.Models;
    using Sentinel.OAuth.Core.Models.OAuth;
    using System;
    using System.Text;

    public class RavenRefreshToken : RefreshToken
    {
        /// <summary>
        /// Initializes a new instance of the Sentinel.OAuth.TokenManagers.RavenDbTokenRepository.Models.OAuth.RavenRefreshToken class.
        /// </summary>
        public RavenRefreshToken()
        {
        }

        /// <summary>
        /// Initializes a new instance of the Sentinel.OAuth.TokenManagers.RavenDbTokenRepository.Models.OAuth.RavenRefreshToken class.
        /// </summary>
        /// <param name="refreshToken">The refresh token.</param>
        public RavenRefreshToken(IRefreshToken refreshToken)
            : base(refreshToken)
        {
            this.Id = Convert.ToBase64String(Encoding.UTF8.GetBytes(refreshToken.ClientId + refreshToken.RedirectUri + refreshToken.Subject + refreshToken.ValidTo.ToString("O")));
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