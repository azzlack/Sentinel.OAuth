namespace Sentinel.OAuth.Core.Interfaces.Models
{
    using System;

    /// <summary>Interface for an OAuth 2 authorization code.</summary>
    public interface IAuthorizationCode : IToken, IEquatable<IAuthorizationCode>
    {
        /// <summary>Gets or sets the code.</summary>
        /// <value>The code.</value>
        string Code { get; set; }

        /// <summary>Gets or sets the ticket.</summary>
        /// <value>The ticket.</value>
        string Ticket { get; set; }
    }
}