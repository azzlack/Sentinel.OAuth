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

    }
}