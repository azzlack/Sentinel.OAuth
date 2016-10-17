namespace Sentinel.OAuth.Core.Interfaces.Repositories
{
    using System.Collections.Generic;
    using System.Threading.Tasks;

    using Sentinel.OAuth.Core.Interfaces.Models;
    using Sentinel.OAuth.Core.Models.OAuth;

    public interface IClientRepository
    {
        /// <summary>Gets the clients in this collection.</summary>
        /// <returns>An enumerator that allows foreach to be used to process the clients in this collection.</returns>
        Task<IEnumerable<IClient>> GetClients();

        /// <summary>Gets the client with the specified id.</summary>
        /// <param name="clientId">Identifier for the client.</param>
        /// <returns>The client.</returns>
        Task<IClient> GetClient(string clientId);

        /// <summary>Updates the specified client.</summary>
        /// <typeparam name="T">The primary key type.</typeparam>
        /// <param name="id">The client identifier.</param>
        /// <param name="client">The client.</param>
        /// <returns>The updated client.</returns>
        Task<IClient> Update<T>(T id, IClient client);

        /// <summary>Creates a new client</summary>
        /// <param name="client">The client.</param>
        /// <returns>The created client.</returns>
        Task<IClient> Create(IClient client);
    }
}