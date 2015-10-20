namespace Sentinel.OAuth.TokenManagers.SqlServerTokenRepository.Models
{
    public class SqlServerTokenRepositoryConfiguration
    {
        /// <summary>
        /// Initializes a new instance of the SqlServerTokenRepositoryConfiguration class.
        /// </summary>
        /// <param name="connectionString">The connection string.</param>
        /// <param name="databaseName">The name of the database.</param>
        public SqlServerTokenRepositoryConfiguration(string connectionString)
        {
            this.ConnectionString = connectionString;
        }

        /// <summary>Gets the connection string.</summary>
        /// <value>The connection string.</value>
        public string ConnectionString { get; private set; }
    }
}