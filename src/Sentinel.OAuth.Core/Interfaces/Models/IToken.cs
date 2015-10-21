namespace Sentinel.OAuth.Core.Interfaces.Models
{
    using System;
    using System.Collections.Generic;

    /// <summary>Interface for a generic token.</summary>
    public interface IToken
    {
        /// <summary>Gets or sets the client id.</summary>
        /// <value>The client id.</value>
        string ClientId { get; set; }

        /// <summary>Gets or sets the subject.</summary>
        /// <value>The subject.</value>
        string Subject { get; set; }

        /// <summary>Gets or sets the redirect URI.</summary>
        /// <value>The redirect URI.</value>
        string RedirectUri { get; set; }

        /// <summary>Gets or sets the scope.</summary>
        /// <value>The scope.</value>
        IEnumerable<string> Scope { get; set; }

        /// <summary>
        /// Gets or sets the expiration time.
        /// </summary>
        /// <value>The expiration time.</value>
        DateTimeOffset ValidTo { get; set; }

        /// <summary>Gets the identifier.</summary>
        /// <returns>The identifier.</returns>
        string GetIdentifier();

        /// <summary>Check if this object is valid.</summary>
        /// <returns><c>true</c> if valid, <c>false</c> if not.</returns>
        bool IsValid();
    }
}