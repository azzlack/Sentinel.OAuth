namespace Sentinel.OAuth.UserManagers.SqlServerUserManager.Models
{
    public class SqlServerUserManagerConfiguration
    {
        /// <summary>
        /// Initializes a new instance of the
        /// Sentinel.OAuth.UserManagers.SqlServerUserManager.Models.SqlServerUserManagerConfiguration
        /// class.
        /// </summary>
        /// <param name="connectionString">The connection string.</param>
        /// <param name="databaseName">The name of the database.</param>
        public SqlServerUserManagerConfiguration(string connectionString, string databaseName)
        {
            this.ConnectionString = connectionString;
            this.DatabaseName = databaseName;
        }

        /// <summary>Gets the connection string.</summary>
        /// <value>The connection string.</value>
        public string ConnectionString { get; private set; }

        /// <summary>Gets the name of the database.</summary>
        /// <value>The name of the database.</value>
        public string DatabaseName { get; private set; }
    }
}