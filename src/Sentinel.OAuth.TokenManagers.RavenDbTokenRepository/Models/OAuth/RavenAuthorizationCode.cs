namespace Sentinel.OAuth.TokenManagers.RavenDbTokenRepository.Models.OAuth
{
    using Sentinel.OAuth.Core.Interfaces.Models;
    using Sentinel.OAuth.Core.Models.OAuth;
    using System;
    using System.Text;

    public class RavenAuthorizationCode : AuthorizationCode
    {
        /// <summary>The identifier.</summary>
        private string id;

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
            this.id = this.GenerateIdentifier(authorizationCode.ClientId, authorizationCode.RedirectUri, authorizationCode.Subject, authorizationCode.ValidTo);

            this.Created = DateTime.UtcNow;
        }

        /// <summary>Gets or sets the identifier.</summary>
        /// <value>The identifier.</value>
        public string Id => this.id ?? (this.id = this.GenerateIdentifier(this.ClientId, this.RedirectUri, this.Subject, this.ValidTo));

        /// <summary>Gets or sets the created date.</summary>
        /// <value>The created date.</value>
        public DateTime Created { get; set; }

        /// <summary>Gets the identifier.</summary>
        /// <returns>The identifier.</returns>
        public override object GetIdentifier()
        {
            return this.Id;
        }

        /// <summary>Generates an identifier.</summary>
        /// <param name="clientId">Identifier for the client.</param>
        /// <param name="redirectUri">The redirect uri.</param>
        /// <param name="subject">The subject.</param>
        /// <param name="validTo">The valid to Date/Time.</param>
        /// <returns>The identifier.</returns>
        private string GenerateIdentifier(string clientId, string redirectUri, string subject, DateTime validTo)
        {
            return Convert.ToBase64String(Encoding.UTF8.GetBytes(clientId + redirectUri + subject + validTo.ToString("O")));
        }
    }
}