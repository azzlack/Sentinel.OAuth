namespace Sentinel.OAuth.UserManagers.SqlServerUserRepository.Implementation
{
    using System;
    using System.Collections.Generic;
    using System.Data.SqlClient;
    using System.Linq;
    using System.Threading.Tasks;

    using Dapper;

    using Sentinel.OAuth.Core.Interfaces.Models;
    using Sentinel.OAuth.Core.Interfaces.Repositories;
    using Sentinel.OAuth.UserManagers.SqlServerUserRepository.Models;

    public class SqlServerUserApiKeyRepository : IUserApiKeyRepository
    {
        /// <summary>The connection string.</summary>
        private readonly string connectionString;

        /// <summary>Initializes a new instance of the <see cref="SqlServerUserApiKeyRepository" /> class.</summary>
        /// <param name="connectionString">The connection string.</param>
        public SqlServerUserApiKeyRepository(string connectionString)
        {
            this.connectionString = connectionString;
        }

        /// <summary>Gets the api keys for the specified user.</summary>
        /// <param name="userId">The user identifier.</param>
        /// <returns>A collection of api keys.</returns>
        public async Task<IEnumerable<IUserApiKey>> GetForUserAsync(string userId)
        {
            using (var connection = await this.OpenConnection())
            {
                var data =
                    await
                    connection.QueryAsync(
                        "SELECT * FROM UserApiKeys WHERE UserId = @UserId",
                        new { UserId = userId });
                var apiKeys =
                    data.Select(
                        x =>
                        new SqlUserApiKey()
                        {
                            UserId = x.UserId,
                            ApiKey = x.ApiKey,
                            Id = x.Id,
                            Created = x.Created ?? DateTimeOffset.MinValue,
                            LastUsed = x.LastUsed ?? DateTimeOffset.MinValue,
                            Name = x.Description,
                            Description = x.Description
                        });

                return apiKeys;
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