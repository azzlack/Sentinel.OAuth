namespace Sentinel.OAuth.Core.Interfaces.Models
{
    using System;

    public interface IClient : IEquatable<IClient>
    {
        /// <summary>
        /// Gets or sets the id.
        /// </summary>
        /// <value>The id.</value>
        string ClientId { get; set; }

        /// <summary>
        /// Gets or sets the client secret.
        /// </summary>
        /// <value>The client secret.</value>
        string ClientSecret { get; set; }

        /// <summary>
        /// Gets or sets the redirect uri.
        /// </summary>
        /// <value>The redirect uri.</value>
        string RedirectUri { get; set; }
    }
}