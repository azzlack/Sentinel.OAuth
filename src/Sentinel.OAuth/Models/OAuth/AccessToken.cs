namespace Sentinel.OAuth.Models.OAuth
{
    using System;

    using Sentinel.OAuth.Core.Interfaces.Models;

    public class AccessToken : IAccessToken
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="RefreshToken"/> class.
        /// </summary>
        /// <param name="token">The token.</param>
        /// <param name="validTo">The valid to.</param>
        public AccessToken(string token, DateTime validTo)
        {
            this.Token = token;
            this.ValidTo = validTo;
            this.Created = DateTime.UtcNow;
        }

        /// <summary>Gets or sets the identifier.</summary>
        /// <value>The identifier.</value>
        public long Id { get; set; }

        /// <summary>
        /// Gets or sets the id.
        /// </summary>
        /// <value>The id.</value>
        public string ClientId { get; set; }

        /// <summary>
        /// Gets or sets the ticket.
        /// </summary>
        /// <value>The ticket.</value>
        public string Ticket { get; set; }

        /// <summary>
        /// Gets or sets the token.
        /// </summary>
        /// <value>The token.</value>
        public string Token { get; set; }

        /// <summary>
        /// Gets or sets the subject.
        /// </summary>
        /// <value>The subject.</value>
        public string Subject { get; set; }

        /// <summary>
        /// Gets or sets the redirect URI.
        /// </summary>
        /// <value>The redirect URI.</value>
        public string RedirectUri { get; set; }

        /// <summary>
        /// Gets or sets the expiration time.
        /// </summary>
        /// <value>The expiration time.</value>
        public DateTime ValidTo { get; set; }

        /// <summary>
        /// Gets or sets the created date.
        /// </summary>
        /// <value>The created date.</value>
        public DateTime Created { get; set; }
    }
}