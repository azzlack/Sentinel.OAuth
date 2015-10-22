namespace Sentinel.OAuth.TokenManagers.SqlServerTokenRepository.Models
{
    using Sentinel.OAuth.TokenManagers.SqlServerTokenRepository.Interfaces;

    public class SqlServerRepositoryConfiguration : ISqlServerRepositoryConfiguration
    {
        /// <summary>
        /// Initializes a new instance of the SqlServerRepositoryConfiguration class.
        /// </summary>
        /// <param name="connectionString">The connection string.</param>
        /// <param name="databaseName">The name of the database.</param>
        public SqlServerRepositoryConfiguration(string connectionString)
        {
            this.ConnectionString = connectionString;
        }

        /// <summary>Gets the connection string.</summary>
        /// <value>The connection string.</value>
        public string ConnectionString { get; }
    }
}