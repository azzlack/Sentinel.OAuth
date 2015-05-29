namespace Sentinel.OAuth.Core.Interfaces.Models
{
    using System;

    /// <summary>Interface for an OAuth 2 access token.</summary>
    public interface IAccessToken : IToken, IEquatable<IAccessToken>
    {
        /// <summary>Gets or sets the ticket.</summary>
        /// <value>The ticket.</value>
        string Ticket { get; set; }

        /// <summary>Gets or sets the token.</summary>
        /// <value>The token.</value>
        string Token { get; set; }
    }
}