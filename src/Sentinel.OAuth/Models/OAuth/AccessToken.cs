namespace Sentinel.OAuth.Models.OAuth
{
    using System;

    using Sentinel.OAuth.Core.Interfaces.Models;

    public class AccessToken : IAccessToken
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="AccessToken"/> class.
        /// </summary>
        public AccessToken()
        {
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

        /// <summary>Tests if this IAccessToken is considered equal to another.</summary>
        /// <param name="other">The i access token to compare to this object.</param>
        /// <returns>true if the objects are considered equal, false if they are not.</returns>
        public bool Equals(IAccessToken other)
        {
            if (this.ClientId == other.ClientId && this.RedirectUri == other.RedirectUri && this.Subject == other.Subject)
            {
                return true;
            }

            return false;
        }
    }
}