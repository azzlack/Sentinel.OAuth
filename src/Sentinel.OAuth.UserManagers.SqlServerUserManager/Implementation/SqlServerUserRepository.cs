namespace Sentinel.OAuth.UserManagers.SqlServerUserManager.Implementation
{
    using Dapper;
    using Sentinel.OAuth.Core.Interfaces.Models;
    using Sentinel.OAuth.Core.Interfaces.Repositories;
    using Sentinel.OAuth.UserManagers.SqlServerUserManager.Models;
    using System;
    using System.Collections.Generic;
    using System.Data.SqlClient;
    using System.Linq;
    using System.Threading.Tasks;

    public class SqlServerUserRepository : IUserRepository
    {
        /// <summary>The connection string.</summary>
        private readonly string connectionString;

        /// <summary>Initializes a new instance of the <see cref="SqlServerUserRepository" /> class.</summary>
        /// <param name="connectionString">The connection string.</param>
        public SqlServerUserRepository(string connectionString)
        {
            this.connectionString = connectionString;
        }

        /// <summary>Gets the users.</summary>
        /// <returns>The users.</returns>
        public async Task<IEnumerable<IUser>> GetUsers()
        {
            using (var connection = await this.OpenConnection())
            {
                var data =
                    await
                    connection.QueryAsync(
                        "SELECT * FROM Users");
                var users =
                    data.Select(
                        x =>
                        new SqlUser()
                        {
                            UserId = x.UserId,
                            Password = x.Password,
                            Id = x.Id,
                            Created = x.Created ?? DateTimeOffset.MinValue,
                            LastLogin = x.LastLogin ?? DateTimeOffset.MinValue,
                            Enabled = x.Enabled ?? false,
                            FirstName = x.FirstName,
                            LastName = x.LastName
                        });

                return users;
            }
        }

        /// <summary>Gets a user.</summary>
        /// <param name="userId">Identifier for the user.</param>
        /// <returns>The user.</returns>
        public async Task<IUser> GetUser(string userId)
        {
            using (var connection = await this.OpenConnection())
            {
                var data =
                    await
                    connection.QueryAsync(
                        "SELECT * FROM Users WHERE UserId = @UserId",
                        new { UserId = userId });
                var users =
                    data.Select(
                        x =>
                        new SqlUser()
                        {
                            UserId = x.UserId,
                            Password = x.Password,
                            Id = x.Id,
                            Created = x.Created ?? DateTimeOffset.MinValue,
                            LastLogin = x.LastLogin ?? DateTimeOffset.MinValue,
                            Enabled = x.Enabled ?? false,
                            FirstName = x.FirstName,
                            LastName = x.LastName
                        });

                return users.FirstOrDefault();
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