namespace Sentinel.OAuth.Core.Interfaces.Repositories
{
    using Sentinel.OAuth.Core.Interfaces.Models;
    using System.Collections.Generic;
    using System.Threading.Tasks;

    public interface IClientRepository
    {
        /// <summary>Gets the clients in this collection.</summary>
        /// <returns>An enumerator that allows foreach to be used to process the clients in this collection.</returns>
        Task<IEnumerable<IClient>> GetClients();

        /// <summary>Gets the client with the specified id.</summary>
        /// <param name="clientId">Identifier for the client.</param>
        /// <returns>The client.</returns>
        Task<IClient> GetClient(string clientId);
    }
}