namespace Sentinel.OAuth.Core.Interfaces.Repositories
{
    using System.Collections.Generic;
    using System.Threading.Tasks;

    using Sentinel.OAuth.Core.Interfaces.Models;

    public interface IUserApiKeyRepository
    {
        /// <summary>Gets the api keys for the specified user.</summary>
        /// <param name="userId">The user identifier.</param>
        /// <returns>A collection of api keys.</returns>
        Task<IEnumerable<IUserApiKey>> GetForUserAsync(string userId);
    }
}