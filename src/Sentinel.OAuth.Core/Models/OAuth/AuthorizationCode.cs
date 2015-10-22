namespace Sentinel.OAuth.Core.Models.OAuth
{
    using Sentinel.OAuth.Core.Interfaces.Models;
    using System;
    using System.Collections.Generic;

    public class AuthorizationCode : IAuthorizationCode
    {
        /// <summary>Initializes a new instance of the Sentinel.OAuth.Core.Models.OAuth.AuthorizationCode class.</summary>
        public AuthorizationCode()
        {
        }

        /// <summary>Initializes a new instance of the Sentinel.OAuth.Core.Models.OAuth.AuthorizationCode class.</summary>
        /// <param name="authorizationCode">The authorization code.</param>
        public AuthorizationCode(IAuthorizationCode authorizationCode)
        {
            this.ClientId = authorizationCode.ClientId;
            this.RedirectUri = authorizationCode.RedirectUri;
            this.Subject = authorizationCode.Subject;
            this.Code = authorizationCode.Code;
            this.Scope = authorizationCode.Scope;
            this.Ticket = authorizationCode.Ticket;
            this.ValidTo = authorizationCode.ValidTo;
        }

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
        public DateTimeOffset ValidTo { get; set; }

        /// <summary>Gets the identifier.</summary>
        /// <returns>The identifier.</returns>
        public virtual string GetIdentifier()
        {
            return this.Code;
        }

        /// <summary>Check if this object is valid.</summary>
        /// <returns><c>true</c> if valid, <c>false</c> if not.</returns>
        public virtual bool IsValid()
        {
            if (this.ClientId == null
                || this.RedirectUri == null
                || this.Subject == null
                || this.Code == null || this.Ticket == null
                || this.ValidTo == DateTimeOffset.MinValue)
            {
                return false;
            }

            return true;
        }

        /// <summary>Tests if this IAuthorizationCode is considered equal to another.</summary>
        /// <param name="other">The i authorization code to compare to this object.</param>
        /// <returns>true if the objects are considered equal, false if they are not.</returns>
        public virtual bool Equals(IAuthorizationCode other)
        {
            if (this.GetIdentifier() == other.GetIdentifier())
            {
                return true;
            }

            return false;
        }
    }
}