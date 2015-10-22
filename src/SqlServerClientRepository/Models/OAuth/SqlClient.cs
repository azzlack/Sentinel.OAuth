namespace Sentinel.OAuth.ClientManagers.SqlServerClientRepository.Models.OAuth
{
    using System;

    using Sentinel.OAuth.Core.Interfaces.Models;
    using Sentinel.OAuth.Core.Models.OAuth;

    public class SqlClient : Client
    {
        /// <summary>Initializes a new instance of the Sentinel.OAuth.TokenManagers.SqlServerTokenRepository.Models.OAuth.SqlClient class.</summary>
        public SqlClient()
        {
        }

        /// <summary>Initializes a new instance of the Sentinel.OAuth.TokenManagers.SqlServerTokenRepository.Models.OAuth.SqlClient class.</summary>
        /// <param name="client">The client.</param>
        public SqlClient(IClient client)
            : base(client)
        {
            if (client is SqlClient)
            {
                this.Id = ((SqlClient)client).Id;
            }

            this.Created = DateTimeOffset.UtcNow;
        }

        /// <summary>Gets or sets the identifier.</summary>
        /// <value>The identifier.</value>
        public long Id { get; set; }

        /// <summary>Gets or sets the created.</summary>
        /// <value>The created.</value>
        public DateTimeOffset Created { get; set; }
    }
}