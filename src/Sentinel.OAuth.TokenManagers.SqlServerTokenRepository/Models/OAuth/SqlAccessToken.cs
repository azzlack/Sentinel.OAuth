namespace Sentinel.OAuth.TokenManagers.SqlServerTokenRepository.Models.OAuth
{
    using Core.Interfaces.Models;
    using Sentinel.OAuth.Core.Models.OAuth;
    using System;

    public class SqlAccessToken : AccessToken
    {
        /// <summary>
        /// Initializes a new instance of the Sentinel.OAuth.TokenManagers.SqlServerTokenRepository.Models.OAuth.SqlAccessToken class.
        /// </summary>
        public SqlAccessToken()
        {
        }

        /// <summary>
        /// Initializes a new instance of the Sentinel.OAuth.TokenManagers.SqlServerTokenRepository.Models.OAuth.SqlAccessToken class.
        /// </summary>
        /// <param name="accessToken">The access token.</param>
        public SqlAccessToken(IAccessToken accessToken)
            : base(accessToken)
        {
            if (accessToken is SqlAccessToken)
            {
                this.Id = ((SqlAccessToken)accessToken).Id;
            }

            this.Created = DateTime.UtcNow;
        }

        /// <summary>Gets or sets the identifier.</summary>
        /// <value>The identifier.</value>
        public long Id { get; set; }

        /// <summary>
        /// Gets or sets the created date.
        /// </summary>
        /// <value>The created date.</value>
        public DateTime Created { get; set; }

        /// <summary>Gets the identifier.</summary>
        /// <returns>The identifier.</returns>
        public override object GetIdentifier()
        {
            return this.Id;
        }

        /// <summary>Check if this object is valid.</summary>
        /// <returns><c>true</c> if valid, <c>false</c> if not.</returns>
        public override bool IsValid()
        {
            return base.IsValid() && this.Created != DateTime.MinValue;
        }
    }
}