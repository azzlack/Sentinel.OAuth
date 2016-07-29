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
        Task<IEnumerable<IUserApiKey>> GetForUser(string userId);

        /// <summary>Updates the specified api key.</summary>
        /// <typeparam name="T">The primary key type.</typeparam>
        /// <param name="id">The api key identifier.</param>
        /// <param name="apiKey">The api key.</param>
        /// <returns>The updated key.</returns>
        Task<IUserApiKey> Update<T>(T id, IUserApiKey apiKey);
    }
}