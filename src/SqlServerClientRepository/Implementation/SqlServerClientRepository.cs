namespace Sentinel.OAuth.ClientManagers.SqlServerClientRepository.Implementation
{
    using Dapper;
    using Sentinel.OAuth.ClientManagers.SqlServerClientRepository.Models.OAuth;
    using Sentinel.OAuth.Core.Interfaces.Models;
    using Sentinel.OAuth.Core.Interfaces.Repositories;
    using System;
    using System.Collections.Generic;
    using System.Data.SqlClient;
    using System.Linq;
    using System.Threading.Tasks;

    public class SqlServerClientRepository : IClientRepository
    {
        /// <summary>The connection string.</summary>
        private readonly string connectionString;

        /// <summary>Initializes a new instance of the <see cref="SqlServerClientRepository" /> class.</summary>
        /// <param name="connectionString">The connection string.</param>
        public SqlServerClientRepository(string connectionString)
        {
            this.connectionString = connectionString;
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

                var clients =
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

                return clients;
            }
        }

        /// <summary>Gets the client with the specified id.</summary>
        /// <param name="clientId">Identifier for the client.</param>
        /// <returns>The client.</returns>
        public async Task<IClient> GetClient(string clientId)
        {
            using (var connection = await this.OpenConnection())
            {
                var data =
                    await
                    connection.QueryAsync(
                        "SELECT * FROM Clients WHERE ClientId = @ClientId",
                        new { ClientId = clientId });

                var clients =
                    data.Select(
                        x =>
                        new SqlClient()
                        {
                            Id = x.Id,
                            Created = x.Created ?? DateTimeOffset.MinValue,
                            ClientId = x.ClientId,
                            ClientSecret = x.ClientSecret,
                            RedirectUri = x.RedirectUri,
                            Name = x.Name,
                            LastUsed = x.LastUsed ?? DateTimeOffset.MinValue,
                            Enabled = x.Enabled ?? false
                        });

                return clients.FirstOrDefault();
            }
        }

        /// <summary>Opens the connection.</summary>
        /// <returns>A SqlConnection.</returns>
        private async Task<SqlConnection> OpenConnection()
        {
            var connection = new SqlConnection(this.connectionString);
            await connection.OpenAsync();

            return connection;
        }
    }
}