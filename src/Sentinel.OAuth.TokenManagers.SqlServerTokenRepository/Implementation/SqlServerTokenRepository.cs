namespace Sentinel.OAuth.TokenManagers.SqlServerTokenRepository.Implementation
{
    using System;
    using System.Collections.Generic;
    using System.Data.SqlClient;
    using System.Linq;
    using System.Threading.Tasks;

    using Dapper;

    using Sentinel.OAuth.Core.Interfaces.Models;
    using Sentinel.OAuth.Core.Interfaces.Repositories;
    using Sentinel.OAuth.Core.Models.OAuth;
    using Sentinel.OAuth.TokenManagers.SqlServerTokenRepository.Models;
    using Sentinel.OAuth.TokenManagers.SqlServerTokenRepository.Models.OAuth;

    /// <summary>A token repository using a SQL server for storage.</summary>
    public class SqlServerTokenRepository : ITokenRepository
    {
        /// <summary>The configuration.</summary>
        private readonly SqlServerTokenRepositoryConfiguration configuration;

        /// <summary>
        /// Initializes a new instance of the SqlServerTokenRepository class.
        /// </summary>
        /// <param name="configuration">The configuration.</param>
        public SqlServerTokenRepository(SqlServerTokenRepositoryConfiguration configuration)
        {
            this.configuration = configuration;
        }

        /// <summary>
        /// Gets all authorization codes that matches the specified redirect uri and expires after the
        /// specified date. Called when authenticating an authorization code.
        /// </summary>
        /// <param name="redirectUri">The redirect uri.</param>
        /// <param name="expires">The expire date.</param>
        /// <returns>The authorization codes.</returns>
        public async Task<IEnumerable<IAuthorizationCode>> GetAuthorizationCodes(string redirectUri, DateTime expires)
        {
            using (var connection = this.OpenConnection())
            {
                var codes =
                    await
                    connection.QueryAsync<SqlAuthorizationCode>(
                        "SELECT * FROM AuthorizationCodes WHERE RedirectUri = @RedirectUri AND ValidTo > @Expires",
                        new { RedirectUri = redirectUri, Expires = expires });

                return codes;
            }
        }

        /// <summary>
        /// Inserts the specified authorization code. Called when creating an authorization code.
        /// </summary>
        /// <param name="authorizationCode">The authorization code.</param>
        /// <returns>
        /// The inserted authorization code. <c>null</c> if the insertion was unsuccessful.
        /// </returns>
        public async Task<IAuthorizationCode> InsertAuthorizationCode(IAuthorizationCode authorizationCode)
        {
            using (var connection = this.OpenConnection())
            {
                var id =
                    await
                    connection.QueryAsync<long>(
                        "INSERT INTO AuthorizationCodes (ClientId, RedirectUri, Subject, Code, Scope, Ticket, ValidTo, Created) VALUES (@ClientId, @RedirectUri, @Subject, @Code, @Scope, @Ticket, @ValidTo, @Created); SELECT CAST(SCOPE_IDENTITY() as bigint);",
                        new
                            {
                                authorizationCode.ClientId,
                                authorizationCode.RedirectUri,
                                authorizationCode.Subject,
                                authorizationCode.Code,
                                authorizationCode.Scope,
                                authorizationCode.Ticket,
                                authorizationCode.ValidTo,
                                Created = DateTime.UtcNow
                            });

                var entities = await connection.QueryAsync<SqlAuthorizationCode>("SELECT * FROM AuthorizationCodes WHERE Id = @Id", new { Id = id });

                return entities.FirstOrDefault();
            }
        }

        /// <summary>
        /// Deletes the authorization codes that expires before the specified expire date. Called when
        /// creating an authorization code to cleanup.
        /// </summary>
        /// <param name="expires">The expire date.</param>
        /// <returns>The number of deleted codes.</returns>
        public async Task<int> DeleteAuthorizationCodes(DateTime expires)
        {
            using (var connection = this.OpenConnection())
            {
                var rows =
                    await
                    connection.ExecuteAsync(
                        "DELETE FROM AuthorizationCodes WHERE ValidTo > @ValidTo",
                        new { ValidTo = expires });

                return rows;
            }
        }

        /// <summary>
        /// Deletes the specified authorization code. Called when authenticating an authorization code to
        /// prevent re-use.
        /// </summary>
        /// <param name="authorizationCode">The authorization code.</param>
        /// <returns><c>True</c> if successful, <c>false</c> otherwise.</returns>
        public async Task<bool> DeleteAuthorizationCode(IAuthorizationCode authorizationCode)
        {
            var code = (SqlAuthorizationCode)authorizationCode;

            using (var connection = this.OpenConnection())
            {
                var rows =
                    await
                    connection.ExecuteAsync(
                        "DELETE FROM AuthorizationCodes WHERE Id = @Id",
                        new { Id = code.Id });

                return rows == 1;
            }
        }

        /// <summary>
        /// Gets all access tokens that expires **after** the specified date. Called when authenticating
        /// an access token to limit the number of tokens to go through when validating the hash.
        /// </summary>
        /// <param name="expires">The expire date.</param>
        /// <returns>The access tokens.</returns>
        public async Task<IEnumerable<IAccessToken>> GetAccessTokens(DateTime expires)
        {
            using (var connection = this.OpenConnection())
            {
                var tokens =
                    await
                    connection.QueryAsync<SqlAccessToken>(
                        "SELECT * FROM AccessTokens WHERE ValidTo > @Expires",
                        new { Expires = expires });

                return tokens;
            }
        }

        /// <summary>Inserts the specified access token. Called when creating an access token.</summary>
        /// <param name="accessToken">The access token.</param>
        /// <returns>The inserted access token. <c>null</c> if the insertion was unsuccessful.</returns>
        public async Task<IAccessToken> InsertAccessToken(IAccessToken accessToken)
        {
            var token = (SqlAccessToken)accessToken;
            
            using (var connection = this.OpenConnection())
            {
                var id =
                    await
                    connection.QueryAsync<long>(
                        "INSERT INTO AccessTokens (ClientId, RedirectUri, Subject, Token, Ticket, ValidTo, Created) VALUES (@ClientId, @RedirectUri, @Subject, @Token, @Ticket, @ValidTo, @Created); SELECT CAST(SCOPE_IDENTITY() as bigint);",
                        new
                        {
                            token.ClientId,
                            token.RedirectUri,
                            token.Subject,
                            token.Token,
                            token.Ticket,
                            token.ValidTo,
                            token.Created
                        });

                var entities = await connection.QueryAsync<SqlAccessToken>("SELECT * FROM AccessTokens WHERE Id = @Id", new { Id = id });

                return entities.FirstOrDefault();
            }
        }

        /// <summary>
        /// Deletes the access tokens that expires before the specified expire date. Called when creating
        /// an access token to cleanup.
        /// </summary>
        /// <param name="expires">The expire date.</param>
        /// <returns>The number of deleted tokens.</returns>
        public async Task<int> DeleteAccessTokens(DateTime expires)
        {
            using (var connection = this.OpenConnection())
            {
                var rows =
                    await
                    connection.ExecuteAsync(
                        "DELETE FROM AccessTokens WHERE ValidTo < @ValidTo",
                        new { ValidTo = expires });

                return rows;
            }
        }

        /// <summary>Deletes the specified access token.</summary>
        /// <param name="accessToken">The access token.</param>
        /// <returns><c>True</c> if successful, <c>false</c> otherwise.</returns>
        public async Task<bool> DeleteAccessToken(IAccessToken accessToken)
        {
            var token = (SqlAccessToken)accessToken;

            using (var connection = this.OpenConnection())
            {
                var rows =
                    await
                    connection.ExecuteAsync(
                        "DELETE FROM AccessTokens WHERE Id = @Id",
                        new { Id = token.Id });

                return rows == 1;
            }
        }

        /// <summary>
        /// Gets all refresh tokens that matches the specified redirect uri and expires after the
        /// specified date. Called when authentication a refresh token to limit the number of tokens to
        /// go through when validating the hash.
        /// </summary>
        /// <param name="redirectUri">The redirect uri.</param>
        /// <param name="expires">The expire date.</param>
        /// <returns>The refresh tokens.</returns>
        public async Task<IEnumerable<IRefreshToken>> GetRefreshTokens(string redirectUri, DateTime expires)
        {
            using (var connection = this.OpenConnection())
            {
                var tokens =
                    await
                    connection.QueryAsync<SqlRefreshToken>(
                        "SELECT * FROM RefreshTokens WHERE RedirectUri = @RedirectUri AND ValidTo > @Expires",
                        new { RedirectUri = redirectUri, Expires = expires });

                return tokens;
            }
        }

        /// <summary>Inserts the specified refresh token. Called when creating a refresh token.</summary>
        /// <param name="refreshToken">The refresh token.</param>
        /// <returns>The inserted refresh token. <c>null</c> if the insertion was unsuccessful.</returns>
        public async Task<IRefreshToken> InsertRefreshToken(IRefreshToken refreshToken)
        {
            using (var connection = this.OpenConnection())
            {
                var id =
                    await
                    connection.QueryAsync<long>(
                        "INSERT INTO RefreshTokens (ClientId, RedirectUri, Subject, Token, ValidTo, Created) VALUES (@ClientId, @RedirectUri, @Subject, @Token, @ValidTo, @Created); SELECT CAST(SCOPE_IDENTITY() as bigint);",
                        new
                        {
                            refreshToken.ClientId,
                            refreshToken.RedirectUri,
                            refreshToken.Subject,
                            refreshToken.Token,
                            refreshToken.ValidTo,
                            Created = DateTime.UtcNow
                        });

                var entities = await connection.QueryAsync<SqlRefreshToken>("SELECT * FROM RefreshTokens WHERE Id = @Id", new { Id = id });

                return entities.FirstOrDefault();
            }
        }

        /// <summary>
        /// Deletes the refresh tokens that expires before the specified expire date. Called when
        /// creating a refresh token to cleanup.
        /// </summary>
        /// <param name="expires">The expire date.</param>
        /// <returns>The number of deleted tokens.</returns>
        public async Task<int> DeleteRefreshTokens(DateTime expires)
        {
            using (var connection = this.OpenConnection())
            {
                var rows =
                    await
                    connection.ExecuteAsync(
                        "DELETE FROM RefreshTokens WHERE ValidTo < @ValidTo",
                        new { ValidTo = expires });

                return rows;
            }
        }

        /// <summary>
        /// Deletes the specified refresh token. Called when authenticating a refresh token to prevent re-
        /// use.
        /// </summary>
        /// <param name="refreshToken">The refresh token.</param>
        /// <returns><c>True</c> if successful, <c>false</c> otherwise.</returns>
        public async Task<bool> DeleteRefreshToken(IRefreshToken refreshToken)
        {
            var token = (SqlRefreshToken)refreshToken;

            using (var connection = this.OpenConnection())
            {
                var rows =
                    await
                    connection.ExecuteAsync(
                        "DELETE FROM RefreshTokens WHERE Id = @Id",
                        new { Id = token.Id });

                return rows == 1;
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