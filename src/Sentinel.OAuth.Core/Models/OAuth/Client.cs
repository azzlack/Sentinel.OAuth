namespace Sentinel.OAuth.Core.Models.OAuth
{
    using Sentinel.OAuth.Core.Interfaces.Models;
    using System;

    public class Client : IClient
    {
        /// <summary>Initializes a new instance of the Sentinel.OAuth.Core.Models.OAuth.Client class.</summary>
        public Client()
        {
        }

        /// <summary>Initializes a new instance of the Sentinel.OAuth.Core.Models.OAuth.Client class.</summary>
        /// <param name="client">The client.</param>
        public Client(IClient client)
        {
            this.ClientId = client.ClientId;
            this.ClientSecret = client.ClientSecret;
            this.PublicKey = client.PublicKey;
            this.RedirectUri = client.RedirectUri;
            this.Name = client.Name;
            this.LastUsed = client.LastUsed;
            this.Enabled = client.Enabled;
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

        /// <summary>Gets or sets the public key.</summary>
        /// <value>The public key.</value>
        public string PublicKey { get; set; }

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
        public DateTimeOffset LastUsed { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether this Client is enabled.
        /// </summary>
        /// <value><c>true</c> if enabled; otherwise, <c>false</c>.</value>
        public bool Enabled { get; set; }

        /// <summary>Gets the identifier.</summary>
        /// <returns>The identifier.</returns>
        public virtual object GetIdentifier()
        {
            return $"{this.ClientId}|{this.RedirectUri}";
        }

        /// <summary>
        /// Indicates whether the current object is equal to another object of the same type.
        /// </summary>
        /// <param name="other">An object to compare with this object.</param>
        /// <returns>
        /// true if the current object is equal to the <paramref name="other"/> parameter; otherwise,
        /// false.
        /// </returns>
        public virtual bool Equals(IClient other)
        {
            if (this.ClientId == other.ClientId && this.RedirectUri == other.RedirectUri)
            {
                return true;
            }

            return false;
        }
    }
}