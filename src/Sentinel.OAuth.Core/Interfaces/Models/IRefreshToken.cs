namespace Sentinel.OAuth.Core.Interfaces.Models
{
    using System;

    /// <summary>Interface for an OAuth 2 refresh token.</summary>
    public interface IRefreshToken : IToken, IEquatable<IRefreshToken>
    {
        /// <summary>Gets or sets the token.</summary>
        /// <value>The token.</value>
        string Token { get; set; }

        /// <summary>Gets or sets the ticket.</summary>
        /// <value>The ticket.</value>
        string Ticket { get; set; }
    }
}