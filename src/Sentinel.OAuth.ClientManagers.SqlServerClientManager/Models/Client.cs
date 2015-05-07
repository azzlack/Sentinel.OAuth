namespace Sentinel.OAuth.ClientManagers.SqlServerClientManager.Models
{
    using System;

    using Sentinel.OAuth.Core.Interfaces.Models;

    public class Client : IClient
    {
        /// <summary>
        /// Initializes a new instance of the Client class.
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
        /// Gets or sets the redirect uri.
        /// </summary>
        /// <value>The redirect uri.</value>
        public string RedirectUri { get; set; }

        /// <summary>
        /// Gets or sets the name.
        /// </summary>
        /// <value>The name.</value>
        public string Name { get; set; }

        /// <summary>
        /// Gets or sets the last used date.
        /// </summary>
        /// <value>The last used date.</value>
        public DateTime LastUsed { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether this Client is enabled.
        /// </summary>
        /// <value><c>true</c> if enabled; otherwise, <c>false</c>.</value>
        public bool Enabled { get; set; }

        /// <summary>Tests if this IClient is considered equal to another.</summary>
        /// <param name="other">The i client to compare to this object.</param>
        /// <returns>true if the objects are considered equal, false if they are not.</returns>
        public bool Equals(IClient other)
        {
            if (this.ClientId == other.ClientId && this.RedirectUri == other.RedirectUri)
            {
                return true;
            }

            return false;
        }
    }
}