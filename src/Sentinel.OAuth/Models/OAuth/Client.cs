namespace Sentinel.OAuth.Models.OAuth
{
    using System;

    using Sentinel.OAuth.Core.Interfaces.Models;

    /// <summary>An OAuth client.</summary>
    public class Client : IClient
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="Client"/> class.
        /// </summary>
        public Client()
        {
            this.ClientId = Guid.NewGuid().ToString("n");
        }

        /// <summary>
        /// Gets or sets the id.
        /// </summary>
        /// <value>The id.</value>
        public string ClientId { get; set; }

        /// <summary>
        /// Gets or sets the client secret.
        /// </summary>
        /// <value>The client secret.</value>
        public string ClientSecret { get; set; }

        /// <summary>
        /// Gets or sets the name.
        /// </summary>
        /// <value>The name.</value>
        public string Name { get; set; }

        /// <summary>
        /// Gets or sets the description.
        /// </summary>
        /// <value>The description.</value>
        public string Description { get; set; }

        /// <summary>
        /// Gets or sets the icon url.
        /// </summary>
        /// <value>The icon url.</value>
        public string IconUrl { get; set; }

        /// <summary>
        /// Gets or sets the created.
        /// </summary>
        /// <value>The created.</value>
        public DateTime Created { get; set; }

        /// <summary>
        /// Gets or sets the last used date.
        /// </summary>
        /// <value>The last used date.</value>
        public DateTime LastUsed { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether this <see cref="Client"/> is enabled.
        /// </summary>
        /// <value><c>true</c> if enabled; otherwise, <c>false</c>.</value>
        public bool Enabled { get; set; }

        /// <summary>
        /// Gets or sets the redirect uri.
        /// </summary>
        /// <value>The redirect uri.</value>
        public string RedirectUri { get; set; }

    }
}