namespace Sentinel.OAuth.ClientManagers.SqlServerClientManager.Implementation
{
    using Dapper;
    using Sentinel.OAuth.ClientManagers.SqlServerClientManager.Models;
    using Sentinel.OAuth.Core.Constants.Identity;
    using Sentinel.OAuth.Core.Interfaces.Identity;
    using Sentinel.OAuth.Core.Interfaces.Models;
    using Sentinel.OAuth.Core.Interfaces.Providers;
    using Sentinel.OAuth.Core.Interfaces.Repositories;
    using Sentinel.OAuth.Core.Managers;
    using Sentinel.OAuth.Models.Identity;
    using System.Collections.Generic;
    using System.Data.SqlClient;
    using System.Linq;
    using System.Security.Claims;
    using System.Threading.Tasks;

    /// <summary>A Sentinel user manager for storing clients in an SQL Server database.</summary> 
    public class SqlServerClientManager : BaseClientManager
    {
        /// <summary>The configuration.</summary>
        private readonly SqlServerClientManagerConfiguration configuration;

        /// <summary>Initializes a new instance of the SqlServerClientManager class.</summary>
        /// <param name="configuration">The connection string.</param>
        /// <param name="cryptoProvider">The crypto provider.</param>
        /// <param name="clientRepository">The client repository.</param>
        public SqlServerClientManager(SqlServerClientManagerConfiguration configuration, ICryptoProvider cryptoProvider, IClientRepository clientRepository)
            : base(cryptoProvider, clientRepository)
        {
            this.configuration = configuration;
        }

        /// <summary>Gets the clients.</summary>
        /// <returns>The clients.</returns>
        public override async Task<IEnumerable<IClient>> GetClients()
        {
            using (var connection = this.OpenConnection())
            {
                var transaction = connection.BeginTransaction();
                var clients =
                    await
                    connection.QueryAsync<Client>(
                        "SELECT * FROM Clients WHERE Enabled = 1",
                        transaction);

                return clients;
            }
        }

        /// <summary>
        /// Authenticates the client. Used when authenticating with the authorization_code grant type.
        /// </summary>
        /// <param name="clientId">The client id.</param>
        /// <param name="redirectUri">The redirect URI.</param>
        /// <returns>The client principal.</returns>
        public override async Task<ISentinelPrincipal> AuthenticateClientAsync(string clientId, string redirectUri)
        {
            using (var connection = this.OpenConnection())
            {
                var transaction = connection.BeginTransaction();
                var matches =
                    await
                    connection.QueryAsync<Client>(
                        "SELECT * FROM Clients WHERE ClientId = @UserName AND RedirectUri = @RedirectUri AND Enabled = 1",
                        new { UserName = clientId, RedirectUri = redirectUri },
                        transaction);

                if (matches.Any())
                {
                    var principal =
                        new SentinelPrincipal(
                            new SentinelIdentity(
                                AuthenticationType.OAuth,
                                new SentinelClaim(ClaimTypes.Name, clientId)));

                    return principal;
                }

                return SentinelPrincipal.Anonymous;
            }
        }

        /// <summary>
        /// Authenticates the client. Used when authenticating with the client_credentials grant type.
        /// </summary>
        /// <param name="clientId">The client id.</param>
        /// <param name="scope">The redirect URI.</param>
        /// <returns>The client principal.</returns>
        public override async Task<ISentinelPrincipal> AuthenticateClientAsync(string clientId, IEnumerable<string> scope)
        {
            using (var connection = this.OpenConnection())
            {
                var transaction = connection.BeginTransaction();
                var matches =
                    await
                    connection.QueryAsync<Client>(
                        "SELECT * FROM Clients WHERE ClientId = @UserName AND Enabled = 1",
                        new { UserName = clientId },
                        transaction);

                if (matches.Any())
                {
                    var principal =
                        new SentinelPrincipal(
                            new SentinelIdentity(
                                AuthenticationType.OAuth,
                                new SentinelClaim(ClaimTypes.Name, clientId)));

                    return principal;
                }

                return SentinelPrincipal.Anonymous;
            }
        }

        /// <summary>Authenticates the client credentials using client id and secret.</summary>
        /// <param name="clientId">The client id.</param>
        /// <param name="clientSecret">The client secret.</param>
        /// <returns>The client principal.</returns>
        public override async Task<ISentinelPrincipal> AuthenticateClientCredentialsAsync(string clientId, string clientSecret)
        {
            using (var connection = this.OpenConnection())
            {
                var transaction = connection.BeginTransaction();
                var matches =
                    await
                    connection.QueryAsync<Client>(
                        "SELECT * FROM Clients WHERE ClientId = @UserName AND Enabled = 1",
                        new { UserName = clientId },
                        transaction);

                foreach (var client in matches)
                {
                    if (this.CryptoProvider.ValidateHash(clientSecret, client.ClientSecret))
                    {
                        var principal =
                            new SentinelPrincipal(
                                new SentinelIdentity(
                                    AuthenticationType.OAuth,
                                    new SentinelClaim(ClaimTypes.Name, client.ClientId)));

                        return principal;
                    }
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