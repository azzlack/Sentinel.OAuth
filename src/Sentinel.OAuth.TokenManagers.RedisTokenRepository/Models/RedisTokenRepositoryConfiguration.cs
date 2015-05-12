namespace Sentinel.OAuth.TokenManagers.RedisTokenRepository.Models
{
    using StackExchange.Redis;

    public class RedisTokenRepositoryConfiguration
    {
        /// <summary>
        /// Initializes a new instance of the RedisTokenRepositoryConfiguration class. This class should
        /// be re-used across your application. Ie. register as singleton if using DI.
        /// </summary>
        /// <param name="connectionString">The connection string.</param>
        /// <param name="database">The database.</param>
        /// <param name="prefix">The prefix.</param>
        public RedisTokenRepositoryConfiguration(string connectionString, int database, string prefix)
        {
            this.Connection = ConnectionMultiplexer.Connect(connectionString);
            this.Database = database;

            this.AccessTokenPrefix = string.Format("{0}:accesstokens", prefix);
            this.RefreshTokenPrefix = string.Format("{0}:refreshtokens", prefix);
            this.AuthorizationCodePrefix = string.Format("{0}:authorizationcodes", prefix);
        }

        /// <summary>Gets the connection.</summary>
        /// <value>The connection.</value>
        public ConnectionMultiplexer Connection { get; private set; }

        /// <summary>Gets the database.</summary>
        /// <value>The database.</value>
        public int Database { get; private set; }

        /// <summary>Gets the access token prefix.</summary>
        /// <value>The access token prefix.</value>
        public string AccessTokenPrefix { get; private set; }

        /// <summary>Gets the refresh token prefix.</summary>
        /// <value>The refresh token prefix.</value>
        public string RefreshTokenPrefix { get; private set; }

        /// <summary>Gets the authorization code prefix.</summary>
        /// <value>The authorization code prefix.</value>
        public string AuthorizationCodePrefix { get; private set; }
    }
}