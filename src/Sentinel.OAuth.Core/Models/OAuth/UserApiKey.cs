namespace Sentinel.OAuth.Core.Models.OAuth
{
    using System;

    using Sentinel.OAuth.Core.Interfaces.Models;

    public class UserApiKey : IUserApiKey
    {
        /// <summary>Initializes a new instance of the <see cref="UserApiKey" /> class.</summary>
        public UserApiKey()
        {
        }

        /// <summary>Initializes a new instance of the <see cref="UserApiKey" /> class.</summary>
        /// <param name="userApiKey">The user api key.</param>
        public UserApiKey(IUserApiKey userApiKey)
        {
            this.UserId = userApiKey.UserId;
            this.ApiKey = userApiKey.ApiKey;
            this.Name = userApiKey.Name;
            this.Description = userApiKey.Description;
            this.LastUsed = userApiKey.LastUsed;
        }

        /// <summary>Gets or sets the identifier of the userApiKey.</summary>
        /// <value>The identifier of the userApiKey.</value>
        public string UserId { get; set; }

        /// <summary>Gets or sets the api key.</summary>
        /// <value>The api key.</value>
        public string ApiKey { get; set; }

        /// <summary>Gets or sets the api key name.</summary>
        /// <value>The api key name.</value>
        public string Name { get; set; }

        /// <summary>Gets or sets the api key description.</summary>
        /// <value>The api key description.</value>
        public string Description { get; set; }

        /// <summary>Gets or sets the last used date.</summary>
        /// <value>The last used date.</value>
        public DateTimeOffset LastUsed { get; set; }

        /// <summary>Gets the identifier.</summary>
        /// <returns>The identifier.</returns>
        public virtual string GetIdentifier()
        {
            return $"{this.UserId}|{this.Name}";
        }

        /// <summary>
        /// Indicates whether the current object is equal to another object of the same type.
        /// </summary>
        /// <param name="other">An object to compare with this object.</param>
        /// <returns>
        /// true if the current object is equal to the <paramref name="other"/> parameter; otherwise,
        /// false.
        /// </returns>
        public virtual bool Equals(IUserApiKey other)
        {
            if (this.UserId == other.UserId && this.Name == other.Name)
            {
                return true;
            }

            return false;
        }
    }
}