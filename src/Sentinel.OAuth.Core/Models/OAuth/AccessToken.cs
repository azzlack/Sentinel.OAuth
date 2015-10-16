namespace Sentinel.OAuth.Core.Models.OAuth
{
    using Sentinel.OAuth.Core.Interfaces.Models;
    using System;
    using System.Collections.Generic;

    public class AccessToken : IAccessToken
    {
        /// <summary>Initializes a new instance of the Sentinel.OAuth.Core.Models.OAuth.AccessToken class.</summary>
        public AccessToken()
        {
        }

        /// <summary>Initializes a new instance of the Sentinel.OAuth.Core.Models.OAuth.AccessToken class.</summary>
        /// <param name="accessToken">The access token.</param>
        public AccessToken(IAccessToken accessToken)
        {
            this.ClientId = accessToken.ClientId;
            this.RedirectUri = accessToken.RedirectUri;
            this.Subject = accessToken.Subject;
            this.Token = accessToken.Token;
            this.Ticket = accessToken.Ticket;
            this.ValidTo = accessToken.ValidTo;
            this.Scope = accessToken.Scope;
        }

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

        /// <summary>Gets or sets the scope.</summary>
        /// <value>The scope.</value>
        public IEnumerable<string> Scope { get; set; }

        /// <summary>
        /// Gets or sets the expiration time.
        /// </summary>
        /// <value>The expiration time.</value>
        public DateTime ValidTo { get; set; }

        /// <summary>Check if this object is valid.</summary>
        /// <returns><c>true</c> if valid, <c>false</c> if not.</returns>
        public virtual bool IsValid()
        {
            if (this.ClientId == null
                || (this.RedirectUri == null && this.Scope == null)
                || this.Subject == null
                || this.Token == null
                || this.Ticket == null
                || this.ValidTo == DateTime.MinValue)
            {
                return false;
            }

            return true;
        }

        /// <summary>Tests if this IAccessToken is considered equal to another.</summary>
        /// <param name="other">The i access token to compare to this object.</param>
        /// <returns>true if the objects are considered equal, false if they are not.</returns>
        public bool Equals(IAccessToken other)
        {
            if (this.ClientId == other.ClientId && this.RedirectUri == other.RedirectUri && this.Subject == other.Subject && this.ValidTo == other.ValidTo)
            {
                return true;
            }

            return false;
        }
    }
}