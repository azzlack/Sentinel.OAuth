namespace Sentinel.OAuth.Core.Interfaces.Models
{
    using System;

    using Sentinel.OAuth;

    public interface IClient
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
        /// Gets or sets the name.
        /// </summary>
        /// <value>The name.</value>
        string Name { get; set; }

        /// <summary>
        /// Gets or sets the description.
        /// </summary>
        /// <value>The description.</value>
        string Description { get; set; }

        /// <summary>
        /// Gets or sets the icon url.
        /// </summary>
        /// <value>The icon url.</value>
        string IconUrl { get; set; }

        /// <summary>
        /// Gets or sets the created.
        /// </summary>
        /// <value>The created.</value>
        DateTime Created { get; set; }

        /// <summary>
        /// Gets or sets the last used date.
        /// </summary>
        /// <value>The last used date.</value>
        DateTime LastUsed { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether this <see cref="Sentinel.OAuth.Models.OAuth.Client"/> is enabled.
        /// </summary>
        /// <value><c>true</c> if enabled; otherwise, <c>false</c>.</value>
        bool Enabled { get; set; }

        /// <summary>
        /// Gets or sets the redirect uri.
        /// </summary>
        /// <value>The redirect uri.</value>
        string RedirectUri { get; set; }
    }
}