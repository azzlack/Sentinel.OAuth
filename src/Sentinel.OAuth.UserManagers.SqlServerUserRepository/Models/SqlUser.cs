namespace Sentinel.OAuth.UserManagers.SqlServerUserRepository.Models
{
    using System;

    using Sentinel.OAuth.Core.Interfaces.Models;
    using Sentinel.OAuth.Core.Models.OAuth;

    public class SqlUser : User
    {
        /// <summary>Initializes a new instance of the Sentinel.OAuth.TokenManagers.SqlServerTokenRepository.Models.OAuth.SqlUser class.</summary>
        public SqlUser()
        {
        }

        /// <summary>Initializes a new instance of the Sentinel.OAuth.TokenManagers.SqlServerTokenRepository.Models.OAuth.SqlUser class.</summary>
        /// <param name="user">The user.</param>
        public SqlUser(IUser user)
            : base(user)
        {
            if (user is SqlUser)
            {
                this.Id = ((SqlUser)user).Id;
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