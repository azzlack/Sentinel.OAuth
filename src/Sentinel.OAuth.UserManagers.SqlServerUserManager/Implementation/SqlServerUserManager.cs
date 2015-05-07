namespace Sentinel.OAuth.UserManagers.SqlServerUserManager.Implementation
{
    using System;
    using System.Data.SqlClient;
    using System.Linq;
    using System.Security.Claims;
    using System.Threading.Tasks;

    using Dapper;

    using Sentinel.OAuth.Core.Constants.Identity;
    using Sentinel.OAuth.Core.Interfaces.Identity;
    using Sentinel.OAuth.Core.Interfaces.Providers;
    using Sentinel.OAuth.Core.Managers;
    using Sentinel.OAuth.Models.Identity;
    using Sentinel.OAuth.UserManagers.SqlServerUserManager.Models;

    /// <summary>A Sentinel user manager for storing users in an SQL Server database.</summary>
    public class SqlServerUserManager : BaseUserManager
    {
        /// <summary>The configuration.</summary>
        private readonly SqlServerUserManagerConfiguration configuration;

        /// <summary>Initializes a new instance of the SqlServerUserManager class.</summary>
        /// <param name="configuration">The connection string.</param>
        /// <param name="cryptoProvider">The crypto provider.</param>
        public SqlServerUserManager(SqlServerUserManagerConfiguration configuration, ICryptoProvider cryptoProvider)
            : base (cryptoProvider)
        {
            this.configuration = configuration;
        }

        /// <summary>Authenticates the user using username and password.</summary>
        /// <param name="username">The username.</param>
        /// <param name="password">The password.</param>
        /// <returns>The client principal.</returns>
        /// <exception cref="SqlException">Parallel transactions are not allowed when using Multiple Active Result Sets (MARS).</exception>
        public async override Task<ISentinelPrincipal> AuthenticateUserWithPasswordAsync(string username, string password)
        {
            using (var connection = this.OpenConnection())
            {
                var transaction = connection.BeginTransaction();
                var matches =
                    await
                    connection.QueryAsync<User>(
                        "SELECT * FROM Users WHERE UserName = @UserName",
                        new { UserName = username }, 
                        transaction);
                var user = matches.FirstOrDefault();

                if (user != null && this.CryptoProvider.ValidateHash(password, user.Password))
                {
                    var principal =
                        new SentinelPrincipal(
                            new SentinelIdentity(
                                AuthenticationType.OAuth,
                                new SentinelClaim(ClaimTypes.Name, user.Username),
                                new SentinelClaim(ClaimTypes.GivenName, user.FirstName),
                                new SentinelClaim(ClaimTypes.Surname, user.LastName)));

                    // Update last login date
                    await
                        connection.ExecuteAsync(
                            "UPDATE Users SET LastLogin = @LastLogin WHERE Username = @Username",
                            new { LastLogin = DateTime.UtcNow, Username = user.Username },
                            transaction);

                    return principal;
                }

                return SentinelPrincipal.Anonymous;
            }
        }

        /// <summary>Opens the connection.</summary>
        /// <returns>A SqlConnection.</returns>
        private SqlConnection OpenConnection()
        {
            var connection = new SqlConnection(this.configuration.ConnectionString);
            connection.Open();

            connection.Execute("USE " + this.configuration.DatabaseName);

            return connection;
        }
    }
}