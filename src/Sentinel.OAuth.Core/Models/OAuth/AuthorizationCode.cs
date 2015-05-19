namespace Sentinel.OAuth.Core.Models.OAuth
{
    using System;
    using System.Collections.Generic;

    using Sentinel.OAuth.Core.Interfaces.Models;

    public class AuthorizationCode : IAuthorizationCode
    {
        /// <summary>
        /// Gets or sets the client id.
        /// </summary>
        /// <value>The client id.</value>
        public string ClientId { get; set; }

        /// <summary>
        /// Gets or sets the redirect URI.
        /// </summary>
        /// <value>The redirect URI.</value>
        public string RedirectUri { get; set; }

        /// <summary>
        /// Gets or sets the subject.
        /// </summary>
        /// <value>The subject.</value>
        public string Subject { get; set; }

        /// <summary>
        /// Gets or sets the code.
        /// </summary>
        /// <value>The code.</value>
        public string Code { get; set; }

        /// <summary>
        /// Gets or sets the scope.
        /// </summary>
        /// <value>The scope.</value>
        public IEnumerable<string> Scope { get; set; }

        /// <summary>
        /// Gets or sets the ticket.
        /// </summary>
        /// <value>The ticket.</value>
        public string Ticket { get; set; }

        /// <summary>
        /// Gets or sets the expiration time.
        /// </summary>
        /// <value>The expiration time.</value>
        public DateTime ValidTo { get; set; }

        /// <summary>Tests if this IAuthorizationCode is considered equal to another.</summary>
        /// <param name="other">The i authorization code to compare to this object.</param>
        /// <returns>true if the objects are considered equal, false if they are not.</returns>
        public bool Equals(IAuthorizationCode other)
        {
            if (this.ClientId == other.ClientId && this.RedirectUri == other.RedirectUri && this.Subject == other.Subject && this.ValidTo == other.ValidTo)
            {
                return true;
            }

            return false;
        }
    }
}