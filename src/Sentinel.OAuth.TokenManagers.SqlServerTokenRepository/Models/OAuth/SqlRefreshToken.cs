namespace Sentinel.OAuth.TokenManagers.SqlServerTokenRepository.Models.OAuth
{
    using Sentinel.OAuth.Core.Interfaces.Models;
    using Sentinel.OAuth.Core.Models.OAuth;
    using System;

    public class SqlRefreshToken : RefreshToken
    {
        /// <summary>
        /// Initializes a new instance of the Sentinel.OAuth.TokenManagers.SqlServerTokenRepository.Models.OAuth.SqlRefreshToken class.
        /// </summary>
        public SqlRefreshToken()
        {
        }

        /// <summary>
        /// Initializes a new instance of the Sentinel.OAuth.TokenManagers.SqlServerTokenRepository.Models.OAuth.SqlRefreshToken class.
        /// </summary>
        /// <param name="refreshToken">The refresh token.</param>
        public SqlRefreshToken(IRefreshToken refreshToken)
            : base(refreshToken)
        {
            if (refreshToken is SqlRefreshToken)
            {
                this.Id = ((SqlRefreshToken)refreshToken).Id;
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

        /// <summary>Check if this object is valid.</summary>
        /// <returns><c>true</c> if valid, <c>false</c> if not.</returns>
        public override bool IsValid()
        {
            return base.IsValid() && this.Created != DateTime.MinValue;
        }
    }
}