namespace Sentinel.OAuth.Core.Interfaces.Models
{
    using System;

    public interface IUserApiKey : IEquatable<IUserApiKey>
    {
        /// <summary>Gets or sets the identifier of the user.</summary>
        /// <value>The identifier of the user.</value>
        string UserId { get; set; }

        /// <summary>Gets or sets the api key.</summary>
        /// <value>The api key.</value>
        string ApiKey { get; set; }

        /// <summary>Gets or sets the api key name.</summary>
        /// <value>The api key name.</value>
        string Name { get; set; }

        /// <summary>Gets or sets the api key description.</summary>
        /// <value>The api key description.</value>
        string Description { get; set; }

        /// <summary>Gets or sets the last used date.</summary>
        /// <value>The last used date.</value>
        DateTimeOffset LastUsed { get; set; }

        /// <summary>Gets the identifier.</summary>
        /// <returns>The identifier.</returns>
        object GetIdentifier();
    }
}