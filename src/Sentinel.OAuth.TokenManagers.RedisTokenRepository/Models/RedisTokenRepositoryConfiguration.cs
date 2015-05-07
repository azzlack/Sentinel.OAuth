namespace Sentinel.OAuth.TokenManagers.RedisTokenRepository.Models
{
    using StackExchange.Redis;

    public class RedisTokenRepositoryConfiguration
    {
        /// <summary>
        /// Initializes a new instance of the RedisTokenRepositoryConfiguration class.
        /// This class should be re-used across your application. Ie. register as singleton if using DI.
        /// </summary>
        /// <param name="connectionString">The connection string.</param>
        /// <param name="database">The database.</param>
        public RedisTokenRepositoryConfiguration(string connectionString, int database)
        {
            this.Connection = ConnectionMultiplexer.Connect(connectionString);
            this.Database = database;
        }

        /// <summary>Gets the connection.</summary>
        /// <value>The connection.</value>
        public ConnectionMultiplexer Connection { get; private set; }

        /// <summary>Gets the database.</summary>
        /// <value>The database.</value>
        public int Database { get; private set; }
    }
}