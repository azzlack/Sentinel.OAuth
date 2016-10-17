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
        public virtual async Task<IEnumerable<IUserApiKey>> GetForUser(string userId)
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

        /// <summary>Updates the specified api key.</summary>
        /// <typeparam name="T">The primary key type.</typeparam>
        /// <param name="id">The api key identifier.</param>
        /// <param name="apiKey">The api key.</param>
        /// <returns>The updated key.</returns>
        public virtual async Task<IUserApiKey> Update<T>(T id, IUserApiKey apiKey)
        {
            using (var connection = await this.OpenConnection())
            {
                var k = (SqlUserApiKey)apiKey;

                using (var transaction = connection.BeginTransaction())
                {
                    try
                    {
                        connection.Execute(
                            "UPDATE UserApiKeys SET UserId = @UserId, ApiKey = @ApiKey, Name = @Name, Description = @Description, LastUsed = @LastUsed, Created = @Created WHERE Id = @Id",
                            new { Id = id, k.UserId, k.ApiKey, k.Name, k.Description, k.LastUsed, k.Created },
                            transaction);

                        transaction.Commit();

                        var result = await connection.QueryAsync<SqlUserApiKey>("SELECT * FROM UserApiKeys WHERE Id = @Id", new { Id = id });

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

        /// <summary>Creates a new API key.</summary>
        /// <param name="apiKey">The api key.</param>
        /// <returns>The created API key.</returns>
        public async Task<IUserApiKey> Create(IUserApiKey apiKey)
        {
            using (var connection = await this.OpenConnection())
            {
                var k = new SqlUserApiKey(apiKey);

                using (var transaction = connection.BeginTransaction())
                {
                    try
                    {
                        k.Created = DateTimeOffset.UtcNow;

                        var id = connection.ExecuteScalar<long>(
                            "INSERT INTO UserApiKeys (UserId, ApiKey, Name, Description, Created) VALUES (@UserId, @ApiKey, @Name, @Description, @Created); SELECT SCOPE_IDENTITY()",
                            new { k.UserId, k.ApiKey, k.Name, k.Description, Created = k.Created.ToString("s") },
                            transaction);

                        transaction.Commit();

                        var result = await connection.QueryAsync<SqlUserApiKey>("SELECT * FROM UserApiKeys WHERE Id = @Id", new { Id = id });

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