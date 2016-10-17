namespace Sentinel.OAuth.Core.Interfaces.Models
{
    using System;

    public interface IClient : IEquatable<IClient>
    {
        /// <summary>Gets or sets the id.</summary>
        /// <value>The id.</value>
        string ClientId { get; set; }

        /// <summary>Gets or sets the client secret.</summary>
        /// <value>The client secret.</value>
        string ClientSecret { get; set; }

        /// <summary>Gets or sets the public key.</summary>
        /// <value>The public key.</value>
        string PublicKey { get; set; }

        /// <summary>Gets or sets the redirect uri.</summary>
        /// <value>The redirect uri.</value>
        string RedirectUri { get; set; }

        /// <summary>Gets or sets the name.</summary>
        /// <value>The name.</value>
        string Name { get; set; }

        /// <summary>Gets or sets the last used date.</summary>
        /// <value>The last used date.</value>
        DateTimeOffset LastUsed { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether this Client is enabled.
        /// </summary>
        /// <value><c>true</c> if enabled; otherwise, <c>false</c>.</value>
        bool Enabled { get; set; }

        /// <summary>Gets the identifier.</summary>
        /// <returns>The identifier.</returns>
        object GetIdentifier();
    }
}