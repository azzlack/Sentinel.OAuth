namespace Sentinel.OAuth.TokenManagers.RedisTokenRepository.Models
{
    using System;

    public class RedisTokenIdentifier : IEquatable<RedisTokenIdentifier>
    {
        /// <summary>Initializes a new instance of the Sentinel.OAuth.TokenManagers.RedisTokenRepository.Models.RedisTokenIdentifier class.</summary>
        /// <param name="id">The identifier.</param>
        /// <param name="clientId">Identifier for the client.</param>
        /// <param name="redirectUri">The redirect URI.</param>
        /// <param name="subject">The subject.</param>
        public RedisTokenIdentifier(string id, string clientId, string redirectUri, string subject)
        {
            this.Id = id;
            this.ClientId = clientId;
            this.RedirectUri = redirectUri;
            this.Subject = subject;
        }

        /// <summary>Gets or sets the Id.</summary>
        /// <value>The Id.</value>
        public string Id { get; set; }

        /// <summary>Gets or sets the identifier of the client.</summary>
        /// <value>The identifier of the client.</value>
        public string ClientId { get; set; }

        /// <summary>Gets or sets the redirect URI.</summary>
        /// <value>The redirect URI.</value>
        public string RedirectUri { get; set; }

        /// <summary>Gets or sets the subject.</summary>
        /// <value>The subject.</value>
        public string Subject { get; set; }

        /// <summary>
        /// Indicates whether the current object is equal to another object of the same type.
        /// </summary>
        /// <returns>
        /// true if the current object is equal to the <paramref name="other"/> parameter; otherwise, false.
        /// </returns>
        /// <param name="other">An object to compare with this object.</param>
        public bool Equals(RedisTokenIdentifier other)
        {
            if (this.Id != other.Id)
            {
                return false;
            }

            if (this.ClientId != other.ClientId)
            {
                return false;
            }

            if (this.RedirectUri != other.RedirectUri)
            {
                return false;
            }

            if (this.Subject != other.Subject)
            {
                return false;
            }

            return true;
        }
    }
}
