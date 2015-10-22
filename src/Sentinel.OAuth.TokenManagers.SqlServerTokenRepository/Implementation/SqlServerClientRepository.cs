namespace Sentinel.OAuth.TokenManagers.SqlServerTokenRepository.Implementation
{
    using Dapper;
    using Sentinel.OAuth.Core.Interfaces.Models;
    using Sentinel.OAuth.Core.Interfaces.Repositories;
    using Sentinel.OAuth.TokenManagers.SqlServerTokenRepository.Interfaces;
    using Sentinel.OAuth.TokenManagers.SqlServerTokenRepository.Models.OAuth;
    using System.Collections.Generic;
    using System.Data.SqlClient;
    using System.Linq;
    using System.Threading.Tasks;

    public class SqlServerClientRepository : IClientRepository
    {
        /// <summary>The configuration.</summary>
        private readonly ISqlServerRepositoryConfiguration configuration;

        /// <summary>
        /// Initializes a new instance of the Sentinel.OAuth.TokenManagers.SqlServerTokenRepository.Implementation.SqlServerClientRepository class.
        /// </summary>
        /// <param name="configuration">The configuration.</param>
        public SqlServerClientRepository(ISqlServerRepositoryConfiguration configuration)
        {
            this.configuration = configuration;
        }

        /// <summary>Gets the clients in this collection.</summary>
        /// <returns>An enumerator that allows foreach to be used to process the clients in this collection.</returns>
        public async Task<IEnumerable<IClient>> GetClients()
        {
            using (var connection = await this.OpenConnection())
            {
                var data =
                    await
                    connection.QueryAsync("SELECT * FROM Clients");

                var tokens =
                    data.Select(
                        x =>
                        new SqlClient()
                        {
                            Id = x.Id,
                            Created = x.Created,
                            ClientId = x.ClientId,
                            ClientSecret = x.ClientSecret,
                            RedirectUri = x.RedirectUri,
                            Name = x.Name,
                            LastUsed = x.LastUsed,
                            Enabled = x.Enabled
                        });

                return tokens;
            }
        }

        /// <summary>Opens the connection.</summary>
        /// <returns>A SqlConnection.</returns>
        private async Task<SqlConnection> OpenConnection()
        {
            var connection = new SqlConnection(this.configuration.ConnectionString);
            await connection.OpenAsync();

            return connection;
        }
    }
}