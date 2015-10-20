namespace Sentinel.OAuth.TokenManagers.SqlServerTokenRepository.Implementation
{
    using Dapper;
    using Newtonsoft.Json;
    using Sentinel.OAuth.Core.Interfaces.Models;
    using Sentinel.OAuth.Core.Interfaces.Repositories;
    using Sentinel.OAuth.TokenManagers.SqlServerTokenRepository.Models;
    using Sentinel.OAuth.TokenManagers.SqlServerTokenRepository.Models.OAuth;
    using System;
    using System.Collections.Generic;
    using System.Data.SqlClient;
    using System.Linq;
    using System.Threading.Tasks;

    /// <summary>A token repository using a SQL server for storage.</summary>
    public class SqlServerTokenRepository : ITokenRepository
    {
        /// <summary>
        /// Initializes a new instance of the SqlServerTokenRepository class.
        /// </summary>
        /// <param name="configuration">The configuration.</param>
        public SqlServerTokenRepository(SqlServerTokenRepositoryConfiguration configuration)
        {
            this.Configuration = configuration;
        }

        /// <summary>Gets the configuration.</summary>
        /// <value>The configuration.</value>
        protected SqlServerTokenRepositoryConfiguration Configuration { get; }

        /// <summary>Gets the specified authorization code.</summary>
        /// <param name="identifier">The identifier.</param>
        /// <returns>The authorization code.</returns>
        public async Task<IAuthorizationCode> GetAuthorizationCode(object identifier)
        {
            if (!(identifier is long))
            {
                throw new ArgumentException("identifier must be a long type", nameof(identifier));
            }

            using (var connection = await this.OpenConnection())
            {
                var data =
                    await
                    connection.QueryAsync(
                        "SELECT * FROM AuthorizationCodes WHERE Id = @Id",
                        new { Id = identifier });
                var codes =
                    data.Select(
                        x =>
                        new SqlAuthorizationCode()
                        {
                            ClientId = x.ClientId,
                            Code = x.Code,
                            Created = x.Created,
                            Id = x.Id,
                            RedirectUri = x.RedirectUri,
                            Subject = x.Subject,
                            Ticket = x.Ticket,
                            ValidTo = x.ValidTo,
                            Scope = x.Scope != null ? x.Scope.ToString().Split(' ') : new string[0]
                        });

                return codes.FirstOrDefault();
            }
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
            using (var connection = await this.OpenConnection())
            {
                var data =
                    await
                    connection.QueryAsync(
                        "SELECT * FROM AuthorizationCodes WHERE RedirectUri = @RedirectUri AND ValidTo > @Expires",
                        new { RedirectUri = redirectUri, Expires = expires });
                var codes =
                    data.Select(
                        x =>
                        new SqlAuthorizationCode()
                        {
                            ClientId = x.ClientId,
                            Code = x.Code,
                            Created = x.Created,
                            Id = x.Id,
                            RedirectUri = x.RedirectUri,
                            Subject = x.Subject,
                            Ticket = x.Ticket,
                            ValidTo = x.ValidTo,
                            Scope = x.Scope != null ? x.Scope.ToString().Split(' ') : new string[0]
                        });

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
            var code = new SqlAuthorizationCode(authorizationCode);

            if (!code.IsValid())
            {
                throw new ArgumentException($"The authorization code is invalid: {JsonConvert.SerializeObject(code)}", nameof(authorizationCode));
            }

            using (var connection = await this.OpenConnection())
            {
                var id =
                    await
                    connection.QueryAsync<long>(
                        "INSERT INTO AuthorizationCodes (ClientId, RedirectUri, Subject, Code, Scope, Ticket, ValidTo, Created) VALUES (@ClientId, @RedirectUri, @Subject, @Code, @Scope, @Ticket, @ValidTo, @Created); SELECT CAST(SCOPE_IDENTITY() as bigint);",
                        new
                        {
                            code.ClientId,
                            code.RedirectUri,
                            code.Subject,
                            code.Code,
                            Scope = code.Scope != null ? string.Join(" ", code.Scope) : null,
                            code.Ticket,
                            code.ValidTo,
                            Created = DateTime.UtcNow
                        });

                var data = await connection.QueryAsync("SELECT * FROM AuthorizationCodes WHERE Id = @Id", new { Id = id });
                var entities =
                    data.Select(
                        x =>
                        new SqlAuthorizationCode()
                        {
                            ClientId = x.ClientId,
                            Code = x.Code,
                            Created = x.Created,
                            Id = x.Id,
                            RedirectUri = x.RedirectUri,
                            Subject = x.Subject,
                            Ticket = x.Ticket,
                            ValidTo = x.ValidTo,
                            Scope = x.Scope != null ? x.Scope.ToString().Split(' ') : new string[0]
                        });

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
            using (var connection = await this.OpenConnection())
            {
                var rows =
                    await
                    connection.ExecuteAsync(
                        "DELETE FROM AuthorizationCodes WHERE ValidTo <= @ValidTo",
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
            var code = new SqlAuthorizationCode(authorizationCode);

            return await this.DeleteAuthorizationCode(code.Id);
        }

        /// <summary>Deletes the specified authorization code.</summary>
        /// <param name="identifier">The identifier.</param>
        /// <returns><c>True</c> if successful, <c>false</c> otherwise.</returns>
        public async Task<bool> DeleteAuthorizationCode(object identifier)
        {
            if (!(identifier is long))
            {
                throw new ArgumentException("identifier must be a long type", nameof(identifier));
            }

            using (var connection = await this.OpenConnection())
            {
                var rows =
                    await
                    connection.ExecuteAsync(
                        "DELETE FROM AuthorizationCodes WHERE Id = @Id",
                        new { Id = identifier });

                return rows == 1;
            }
        }

        /// <summary>Gets the specified access token.</summary>
        /// <param name="identifier">The identifier.</param>
        /// <returns>The access token.</returns>
        public async Task<IAccessToken> GetAccessToken(object identifier)
        {
            if (!(identifier is long))
            {
                throw new ArgumentException("identifier must be a long type", nameof(identifier));
            }

            using (var connection = await this.OpenConnection())
            {
                var data =
                    await
                    connection.QueryAsync(
                        "SELECT * FROM AccessTokens WHERE Id = @Id",
                        new { Id = identifier });
                var tokens =
                    data.Select(
                        x =>
                        new SqlAccessToken()
                        {
                            ClientId = x.ClientId,
                            Created = x.Created,
                            Id = x.Id,
                            RedirectUri = x.RedirectUri,
                            Subject = x.Subject,
                            Token = x.Token,
                            Ticket = x.Ticket,
                            ValidTo = x.ValidTo,
                            Scope = x.Scope != null ? x.Scope.ToString().Split(' ') : new string[0]
                        });

                return tokens.FirstOrDefault();
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
            using (var connection = await this.OpenConnection())
            {
                var data =
                    await
                    connection.QueryAsync(
                        "SELECT * FROM AccessTokens WHERE ValidTo > @Expires",
                        new { Expires = expires });

                var tokens =
                    data.Select(
                        x =>
                        new SqlAccessToken()
                        {
                            ClientId = x.ClientId,
                            Created = x.Created,
                            Id = x.Id,
                            RedirectUri = x.RedirectUri,
                            Subject = x.Subject,
                            Token = x.Token,
                            Ticket = x.Ticket,
                            ValidTo = x.ValidTo,
                            Scope = x.Scope != null ? x.Scope.ToString().Split(' ') : new string[0]
                        });

                return tokens;
            }
        }

        /// <summary>
        /// Gets all access tokens for the specified user that expires **after** the specified date. 
        /// Called when authenticating an access token to limit the number of tokens to go through when validating the hash.
        /// </summary>
        /// <param name="subject">The subject.</param>
        /// <param name="expires">The expire date.</param>
        /// <returns>The access tokens.</returns>
        public async Task<IEnumerable<IAccessToken>> GetAccessTokens(string subject, DateTime expires)
        {
            using (var connection = await this.OpenConnection())
            {
                var data =
                    await
                    connection.QueryAsync(
                        "SELECT * FROM AccessTokens WHERE ValidTo > @Expires AND Subject = @Subject",
                        new { Expires = expires, Subject = subject });

                var tokens =
                    data.Select(
                        x =>
                        new SqlAccessToken()
                        {
                            ClientId = x.ClientId,
                            Created = x.Created,
                            Id = x.Id,
                            RedirectUri = x.RedirectUri,
                            Subject = x.Subject,
                            Token = x.Token,
                            Ticket = x.Ticket,
                            ValidTo = x.ValidTo,
                            Scope = x.Scope != null ? x.Scope.ToString().Split(' ') : new string[0]
                        });

                return tokens;
            }
        }

        /// <summary>Inserts the specified access token. Called when creating an access token.</summary>
        /// <param name="accessToken">The access token.</param>
        /// <returns>The inserted access token. <c>null</c> if the insertion was unsuccessful.</returns>
        public async Task<IAccessToken> InsertAccessToken(IAccessToken accessToken)
        {
            var token = new SqlAccessToken(accessToken);

            // Validate token
            if (!token.IsValid())
            {
                throw new ArgumentException($"The access token is invalid: {JsonConvert.SerializeObject(token)}", nameof(accessToken));
            }

            using (var connection = await this.OpenConnection())
            {
                var id =
                    await
                    connection.QueryAsync<long>(
                        "INSERT INTO AccessTokens (ClientId, RedirectUri, Subject, Scope, Token, Ticket, ValidTo, Created) VALUES (@ClientId, @RedirectUri, @Subject, @Scope, @Token, @Ticket, @ValidTo, @Created); SELECT CAST(SCOPE_IDENTITY() as bigint);",
                        new
                        {
                            token.ClientId,
                            token.RedirectUri,
                            token.Subject,
                            Scope = token.Scope != null ? string.Join(" ", token.Scope) : null,
                            token.Token,
                            token.Ticket,
                            token.ValidTo,
                            token.Created
                        });

                var data = await connection.QueryAsync("SELECT * FROM AccessTokens WHERE Id = @Id", new { Id = id });
                var entities =
                    data.Select(
                        x =>
                        new SqlAccessToken()
                        {
                            ClientId = x.ClientId,
                            Created = x.Created,
                            Id = x.Id,
                            RedirectUri = x.RedirectUri,
                            Subject = x.Subject,
                            Token = x.Token,
                            Ticket = x.Ticket,
                            ValidTo = x.ValidTo,
                            Scope = x.Scope != null ? x.Scope.ToString().Split(' ') : new string[0]
                        });

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
            using (var connection = await this.OpenConnection())
            {
                var rows =
                    await
                    connection.ExecuteAsync(
                        "DELETE FROM AccessTokens WHERE ValidTo <= @ValidTo",
                        new { ValidTo = expires });

                return rows;
            }
        }

        /// <summary>Deletes the access tokens belonging to the specified client, redirect uri and subject.</summary>
        /// <param name="clientId">Identifier for the client.</param>
        /// <param name="redirectUri">The redirect uri.</param>
        /// <param name="subject">The subject.</param>
        /// <returns>The number of deleted tokens.</returns>
        public async Task<int> DeleteAccessTokens(string clientId, string redirectUri, string subject)
        {
            using (var connection = await this.OpenConnection())
            {
                var rows =
                    await
                    connection.ExecuteAsync(
                        "DELETE FROM AccessTokens WHERE ClientId = @ClientId AND RedirectUri = @RedirectUri AND Subject = @Subject",
                        new { ClientId = clientId, RedirectUri = redirectUri, Subject = subject });

                return rows;
            }
        }

        /// <summary>Deletes the specified access token.</summary>
        /// <param name="accessToken">The access token.</param>
        /// <returns><c>True</c> if successful, <c>false</c> otherwise.</returns>
        public async Task<bool> DeleteAccessToken(IAccessToken accessToken)
        {
            var token = new SqlAccessToken(accessToken);

            return await this.DeleteAccessToken(token.Id);
        }

        /// <summary>Deletes the specified access token.</summary>
        /// <param name="identifier">The identifier.</param>
        /// <returns><c>True</c> if successful, <c>false</c> otherwise.</returns>
        public async Task<bool> DeleteAccessToken(object identifier)
        {
            if (!(identifier is long))
            {
                throw new ArgumentException("identifier must be a long type", nameof(identifier));
            }

            using (var connection = await this.OpenConnection())
            {
                var rows =
                    await
                    connection.ExecuteAsync(
                        "DELETE FROM AccessTokens WHERE Id = @Id",
                        new { Id = identifier });

                return rows == 1;
            }
        }

        /// <summary>Gets the specified refresh token.</summary>
        /// <param name="identifier">The identifier.</param>
        /// <returns>The refresh token.</returns>
        public async Task<IRefreshToken> GetRefreshToken(object identifier)
        {
            if (!(identifier is long))
            {
                throw new ArgumentException("identifier must be a long type", nameof(identifier));
            }

            using (var connection = await this.OpenConnection())
            {
                var data =
                    await
                    connection.QueryAsync(
                        "SELECT * FROM RefreshTokens WHERE Id = @Id",
                        new { Id = identifier });
                var tokens =
                    data.Select(
                        x =>
                        new SqlRefreshToken()
                        {
                            ClientId = x.ClientId,
                            Created = x.Created,
                            Id = x.Id,
                            RedirectUri = x.RedirectUri,
                            Subject = x.Subject,
                            Token = x.Token,
                            ValidTo = x.ValidTo,
                            Scope = x.Scope != null ? x.Scope.ToString().Split(' ') : new string[0]
                        });

                return tokens.FirstOrDefault();
            }
        }

        /// <summary>
        /// Gets all refresh tokens that matches the specified redirect uri and expires after the
        /// specified date. Called when authentication a refresh token to limit the number of tokens to
        /// go through when validating the hash.
        /// </summary>
        /// <param name="clientId">Identifier for the client.</param>
        /// <param name="redirectUri">The redirect uri.</param>
        /// <param name="expires">The expire date.</param>
        /// <returns>The refresh tokens.</returns>
        public async Task<IEnumerable<IRefreshToken>> GetRefreshTokens(string clientId, string redirectUri, DateTime expires)
        {
            using (var connection = await this.OpenConnection())
            {
                var data =
                    await
                    connection.QueryAsync(
                        "SELECT * FROM RefreshTokens WHERE ClientId = @ClientId AND RedirectUri = @RedirectUri AND ValidTo > @Expires",
                        new { ClientId = clientId, RedirectUri = redirectUri, Expires = expires });

                var tokens =
                    data.Select(
                        x =>
                        new SqlRefreshToken()
                        {
                            ClientId = x.ClientId,
                            Created = x.Created,
                            Id = x.Id,
                            RedirectUri = x.RedirectUri,
                            Subject = x.Subject,
                            Token = x.Token,
                            ValidTo = x.ValidTo,
                            Scope = x.Scope != null ? x.Scope.ToString().Split(' ') : new string[0]
                        });

                return tokens;
            }
        }

        /// <summary>
        /// Gets all refresh tokens for the specified user that expires **after** the specified date. 
        /// </summary>
        /// <param name="subject">The subject.</param>
        /// <param name="expires">The expire date.</param>
        /// <returns>The refresh tokens.</returns>
        public async Task<IEnumerable<IRefreshToken>> GetRefreshTokens(string subject, DateTime expires)
        {
            using (var connection = await this.OpenConnection())
            {
                var data =
                    await
                    connection.QueryAsync(
                        "SELECT * FROM RefreshTokens WHERE Subject = @Subject AND ValidTo > @Expires",
                        new { Subject = subject, Expires = expires });

                var tokens =
                    data.Select(
                        x =>
                        new SqlRefreshToken()
                        {
                            ClientId = x.ClientId,
                            Created = x.Created,
                            Id = x.Id,
                            RedirectUri = x.RedirectUri,
                            Subject = x.Subject,
                            Token = x.Token,
                            ValidTo = x.ValidTo,
                            Scope = x.Scope != null ? x.Scope.ToString().Split(' ') : new string[0]
                        });

                return tokens;
            }
        }

        /// <summary>Inserts the specified refresh token. Called when creating a refresh token.</summary>
        /// <param name="refreshToken">The refresh token.</param>
        /// <returns>The inserted refresh token. <c>null</c> if the insertion was unsuccessful.</returns>
        public async Task<IRefreshToken> InsertRefreshToken(IRefreshToken refreshToken)
        {
            var token = new SqlRefreshToken(refreshToken);

            // Validate token
            if (!token.IsValid())
            {
                throw new ArgumentException($"The refresh token is invalid: {JsonConvert.SerializeObject(token)}", nameof(refreshToken));
            }

            using (var connection = await this.OpenConnection())
            {
                var id =
                    await
                    connection.QueryAsync<long>(
                        "INSERT INTO RefreshTokens (ClientId, RedirectUri, Subject, Scope, Token, ValidTo, Created) VALUES (@ClientId, @RedirectUri, @Subject, @Scope, @Token, @ValidTo, @Created); SELECT CAST(SCOPE_IDENTITY() as bigint);",
                        new
                        {
                            refreshToken.ClientId,
                            refreshToken.RedirectUri,
                            refreshToken.Subject,
                            Scope = token.Scope != null ? string.Join(" ", token.Scope) : null,
                            refreshToken.Token,
                            refreshToken.ValidTo,
                            Created = DateTime.UtcNow
                        });

                var data = await connection.QueryAsync("SELECT * FROM RefreshTokens WHERE Id = @Id", new { Id = id });

                var entities =
                    data.Select(
                        x =>
                        new SqlRefreshToken()
                        {
                            ClientId = x.ClientId,
                            Created = x.Created,
                            Id = x.Id,
                            RedirectUri = x.RedirectUri,
                            Subject = x.Subject,
                            Token = x.Token,
                            ValidTo = x.ValidTo,
                            Scope = x.Scope != null ? x.Scope.ToString().Split(' ') : new string[0]
                        });

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
            using (var connection = await this.OpenConnection())
            {
                var rows =
                    await
                    connection.ExecuteAsync(
                        "DELETE FROM RefreshTokens WHERE ValidTo <= @ValidTo",
                        new { ValidTo = expires });

                return rows;
            }
        }

        /// <summary>Deletes the refresh tokens belonging to the specified client, redirect uri and subject.</summary>
        /// <param name="clientId">Identifier for the client.</param>
        /// <param name="redirectUri">The redirect uri.</param>
        /// <param name="subject">The subject.</param>
        /// <returns>The number of deleted tokens.</returns>
        public async Task<int> DeleteRefreshTokens(string clientId, string redirectUri, string subject)
        {
            using (var connection = await this.OpenConnection())
            {
                var rows =
                    await
                    connection.ExecuteAsync(
                        "DELETE FROM RefreshTokens WHERE ClientId = @ClientId AND RedirectUri = @RedirectUri AND Subject = @Subject",
                        new { ClientId = clientId, RedirectUri = redirectUri, Subject = subject });

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
            var token = new SqlRefreshToken(refreshToken);

            return await this.DeleteRefreshToken(token.Id);
        }

        /// <summary>Deletes the specified refresh token.</summary>
        /// <param name="identifier">The identifier.</param>
        /// <returns><c>True</c> if successful, <c>false</c> otherwise.</returns>
        public async Task<bool> DeleteRefreshToken(object identifier)
        {
            if (!(identifier is long))
            {
                throw new ArgumentException("identifier must be a long type", nameof(identifier));
            }

            using (var connection = await this.OpenConnection())
            {
                var rows =
                    await
                    connection.ExecuteAsync(
                        "DELETE FROM RefreshTokens WHERE Id = @Id",
                        new { Id = identifier });

                return rows == 1;
            }
        }

        /// <summary>Deletes all access tokens, refresh tokens and authorization codes.</summary>
        /// <returns><c>True</c> if successful, <c>false</c> otherwise.</returns>
        public async Task<bool> Purge()
        {
            using (var connection = await this.OpenConnection())
            {
                await connection.ExecuteAsync("TRUNCATE TABLE AuthorizationCodes;TRUNCATE TABLE AccessTokens;TRUNCATE TABLE RefreshTokens");

                return true;
            }
        }

        /// <summary>Opens the connection.</summary>
        /// <returns>A SqlConnection.</returns>
        private async Task<SqlConnection> OpenConnection()
        {
            var connection = new SqlConnection(this.Configuration.ConnectionString);
            await connection.OpenAsync();

            return connection;
        }
    }
}