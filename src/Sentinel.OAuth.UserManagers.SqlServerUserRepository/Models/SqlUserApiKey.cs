namespace Sentinel.OAuth.UserManagers.SqlServerUserRepository.Models
{
    using System;

    using Sentinel.OAuth.Core.Interfaces.Models;
    using Sentinel.OAuth.Core.Models.OAuth;

    public class SqlUserApiKey : UserApiKey
    {
        /// <summary>Initializes a new instance of the <see cref="SqlUserApiKey" /> class.</summary>
        public SqlUserApiKey()
        {
        }

        /// <summary>Initializes a new instance of the <see cref="SqlUserApiKey" /> class.</summary>
        /// <param name="userApiKey">The user api key.</param>
        public SqlUserApiKey(IUserApiKey userApiKey)
            : base(userApiKey)
        {
            if (userApiKey is SqlUserApiKey)
            {
                this.Id = ((SqlUserApiKey)userApiKey).Id;
            }

            this.Created = DateTimeOffset.UtcNow;
        }

        /// <summary>Gets or sets the identifier.</summary>
        /// <value>The identifier.</value>
        public long Id { get; set; }

        /// <summary>Gets or sets the created.</summary>
        /// <value>The created.</value>
        public DateTimeOffset Created { get; set; }
    }
}