namespace Sentinel.OAuth.Core.Interfaces.Models
{
    using System;
    using System.Collections.Generic;

    /// <summary>Interface for an OAuth 2 authorization code.</summary>
    public interface IAuthorizationCode
    {
        /// <summary>
        /// Gets or sets the client id.
        /// </summary>
        /// <value>The client id.</value>
        string ClientId { get; set; }

        /// <summary>
        /// Gets or sets the redirect URI.
        /// </summary>
        /// <value>The redirect URI.</value>
        string RedirectUri { get; set; }

        /// <summary>
        /// Gets or sets the subject.
        /// </summary>
        /// <value>The subject.</value>
        string Subject { get; set; }

        /// <summary>
        /// Gets or sets the code.
        /// </summary>
        /// <value>The code.</value>
        string Code { get; set; }

        /// <summary>
        /// Gets or sets the scope.
        /// </summary>
        /// <value>The scope.</value>
        IEnumerable<string> Scope { get; set; }

        /// <summary>
        /// Gets or sets the ticket.
        /// </summary>
        /// <value>The ticket.</value>
        string Ticket { get; set; }

        /// <summary>
        /// Gets or sets the expiration time.
        /// </summary>
        /// <value>The expiration time.</value>
        DateTime ValidTo { get; set; } 
    }
}