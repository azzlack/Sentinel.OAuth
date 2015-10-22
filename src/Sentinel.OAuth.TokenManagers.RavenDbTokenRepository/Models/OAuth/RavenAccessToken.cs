namespace Sentinel.OAuth.TokenManagers.RavenDbTokenRepository.Models.OAuth
{
    using Core.Interfaces.Models;
    using Sentinel.OAuth.Core.Models.OAuth;
    using System;

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
        /// <param name="accessToken">The access accessToken.</param>
        public RavenAccessToken(IAccessToken accessToken)
            : base(accessToken)
        {
            this.Created = DateTimeOffset.UtcNow;
        }

        /// <summary>Gets or sets the identifier.</summary>
        /// <value>The identifier.</value>
        public string Id { get; set; }

        /// <summary>
        /// Gets or sets the created date.
        /// </summary>
        /// <value>The created date.</value>
        public DateTimeOffset Created { get; set; }
    }
}