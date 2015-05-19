namespace Sentinel.OAuth.TokenManagers.SqlServerTokenRepository.Models.OAuth
{
    using System;

    using Sentinel.OAuth.Core.Models.OAuth;

    public class SqlAuthorizationCode : AuthorizationCode
    {
        /// <summary>Gets or sets the identifier.</summary>
        /// <value>The identifier.</value>
        public long Id { get; set; }

        /// <summary>
        /// Gets or sets the created date.
        /// </summary>
        /// <value>The created date.</value>
        public DateTime Created { get; set; }
    }
}