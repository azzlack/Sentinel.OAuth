namespace Sentinel.OAuth.TokenManagers.RavenDbTokenRepository.Models.OAuth
{
    using Sentinel.OAuth.Core.Interfaces.Models;
    using Sentinel.OAuth.Core.Models.OAuth;
    using System;

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
            this.Created = DateTimeOffset.UtcNow;
        }

        /// <summary>
        /// Gets or sets the created date.
        /// </summary>
        /// <value>The created date.</value>
        public DateTimeOffset Created { get; set; }
    }
}