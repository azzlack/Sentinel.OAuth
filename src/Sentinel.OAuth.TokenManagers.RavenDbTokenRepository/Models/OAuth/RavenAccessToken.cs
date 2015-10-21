namespace Sentinel.OAuth.TokenManagers.RavenDbTokenRepository.Models.OAuth
{
    using Core.Interfaces.Models;
    using Sentinel.OAuth.Core.Models.OAuth;
    using System;
    using System.Text;

    public class RavenAccessToken : AccessToken
    {
        /// <summary>The identifier.</summary>
        private string id;

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
            this.id = this.GenerateIdentifier(accessToken.ClientId, accessToken.RedirectUri, accessToken.Subject, accessToken.ValidTo);

            this.Created = DateTimeOffset.UtcNow;
        }

        /// <summary>Gets the identifier.</summary>
        /// <value>The identifier.</value>
        public string Id => this.id ?? (this.id = this.GenerateIdentifier(this.ClientId, this.RedirectUri, this.Subject, this.ValidTo));

        /// <summary>
        /// Gets or sets the created date.
        /// </summary>
        /// <value>The created date.</value>
        public DateTimeOffset Created { get; set; }

        /// <summary>Generates an identifier.</summary>
        /// <param name="clientId">Identifier for the client.</param>
        /// <param name="redirectUri">The redirect uri.</param>
        /// <param name="subject">The subject.</param>
        /// <param name="validTo">The valid to Date/Time.</param>
        /// <returns>The identifier.</returns>
        private string GenerateIdentifier(string clientId, string redirectUri, string subject, DateTimeOffset validTo)
        {
            return Convert.ToBase64String(Encoding.UTF8.GetBytes(clientId + redirectUri + subject + validTo.ToString("O")));
        }
    }
}