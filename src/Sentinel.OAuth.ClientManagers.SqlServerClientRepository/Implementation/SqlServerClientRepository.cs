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
        public virtual async Task<IEnumerable<IClient>> GetClients()
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
                            Created = x.Created ?? DateTimeOffset.MinValue,
                            ClientId = x.ClientId,
                            ClientSecret = x.ClientSecret,
                            RedirectUri = x.RedirectUri,
                            Name = x.Name,
                            LastUsed = x.LastUsed ?? DateTimeOffset.MinValue,
                            Enabled = x.Enabled ?? false
                        });

                return clients;
            }
        }

        /// <summary>Gets the client with the specified id.</summary>
        /// <param name="clientId">Identifier for the client.</param>
        /// <returns>The client.</returns>
        public virtual async Task<IClient> GetClient(string clientId)
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

        /// <summary>Updates the specified client.</summary>
        /// <typeparam name="T">The primary key type.</typeparam>
        /// <param name="id">The client identifier.</param>
        /// <param name="client">The client.</param>
        /// <returns>The updated client.</returns>
        public virtual async Task<IClient> Update<T>(T id, IClient client)
        {
            using (var connection = await this.OpenConnection())
            {
                var k = (SqlClient)client;

                using (var transaction = connection.BeginTransaction())
                {
                    try
                    {
                        connection.Execute(
                            "UPDATE Clients SET ClientId = @ClientId, ClientSecret = @ClientSecret, Name = @Name, RedirectUri = @RedirectUri, Enabled = @Enabled, LastUsed = @LastUsed, Created = @Created WHERE Id = @Id",
                            new { Id = id, k.ClientId, k.ClientSecret, k.Name, k.RedirectUri, k.Enabled, k.LastUsed, k.Created },
                            transaction);

                        transaction.Commit();

                        var result = await connection.QueryAsync<SqlClient>("SELECT * FROM Clients WHERE Id = @Id", new { Id = id });

                        return result.FirstOrDefault();
                    }
                    catch (Exception)
                    {
                        transaction.Rollback();
                        throw;
                    }
                }
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