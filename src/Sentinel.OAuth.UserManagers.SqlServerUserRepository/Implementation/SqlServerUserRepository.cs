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
        public virtual async Task<IEnumerable<IUser>> GetUsers()
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
        public virtual async Task<IUser> GetUser(string userId)
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

        /// <summary>Updates the specified user.</summary>
        /// <typeparam name="T">The primary key type.</typeparam>
        /// <param name="id">The user identifier.</param>
        /// <param name="user">The user.</param>
        /// <returns>The updated user.</returns>
        public virtual async Task<IUser> Update<T>(T id, IUser user)
        {
            using (var connection = await this.OpenConnection())
            {
                var k = (SqlUser)user;

                using (var transaction = connection.BeginTransaction())
                {
                    try
                    {
                        connection.Execute(
                            "UPDATE Users SET UserId = @UserId, Password = @Password, FirstName = @FirstName, LastName = @LastName, Enabled = @Enabled, LastLogin = @LastLogin, Created = @Created WHERE Id = @Id",
                            new { Id = id, k.UserId, k.Password, k.FirstName, k.LastName, k.Enabled, k.LastLogin, k.Created },
                            transaction);

                        transaction.Commit();

                        var result = await connection.QueryAsync<SqlUser>("SELECT * FROM Users WHERE Id = @Id", new { Id = id });

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