namespace Sentinel.OAuth.TokenManagers.SqlServerTokenRepository.Models.OAuth
{
    using Core.Interfaces.Models;
    using Sentinel.OAuth.Core.Models.OAuth;
    using System;

    public class SqlAuthorizationCode : AuthorizationCode
    {
        /// <summary>
        /// Initializes a new instance of the Sentinel.OAuth.TokenManagers.SqlServerTokenRepository.Models.OAuth.SqlAuthorizationCode class.
        /// </summary>
        public SqlAuthorizationCode()
        {
        }

        /// <summary>
        /// Initializes a new instance of the Sentinel.OAuth.TokenManagers.SqlServerTokenRepository.Models.OAuth.SqlAuthorizationCode class.
        /// </summary>
        /// <param name="authorizationCode">The authorization code.</param>
        public SqlAuthorizationCode(IAuthorizationCode authorizationCode)
            : base(authorizationCode)
        {
            if (authorizationCode is SqlAuthorizationCode)
            {
                this.Id = ((SqlAuthorizationCode)authorizationCode).Id;
            }

            this.Created = DateTimeOffset.UtcNow;
        }

        /// <summary>Gets or sets the identifier.</summary>
        /// <value>The identifier.</value>
        public long Id { get; set; }

        /// <summary>
        /// Gets or sets the created date.
        /// </summary>
        /// <value>The created date.</value>
        public DateTimeOffset Created { get; set; }

        /// <summary>Check if this object is valid.</summary>
        /// <returns><c>true</c> if valid, <c>false</c> if not.</returns>
        public override bool IsValid()
        {
            return base.IsValid() && this.Created != DateTimeOffset.MinValue;
        }
    }
}