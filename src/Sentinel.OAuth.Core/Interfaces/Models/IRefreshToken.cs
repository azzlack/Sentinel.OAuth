namespace Sentinel.OAuth.Core.Interfaces.Models
{
    using System;

    /// <summary>Interface for an OAuth 2 refresh token.</summary>
    public interface IRefreshToken : IEquatable<IRefreshToken>
    {
        /// <summary>
        /// Gets or sets the id.
        /// </summary>
        /// <value>The id.</value>
        string ClientId { get; set; }

        /// <summary>
        /// Gets or sets the token.
        /// </summary>
        /// <value>The token.</value>
        string Token { get; set; }

        /// <summary>
        /// Gets or sets the subject.
        /// </summary>
        /// <value>The subject.</value>
        string Subject { get; set; }

        /// <summary>
        /// Gets or sets the redirect URI.
        /// </summary>
        /// <value>The redirect URI.</value>
        string RedirectUri { get; set; }

        /// <summary>
        /// Gets or sets the expiration time.
        /// </summary>
        /// <value>The expiration time.</value>
        DateTime ValidTo { get; set; }
    }
}