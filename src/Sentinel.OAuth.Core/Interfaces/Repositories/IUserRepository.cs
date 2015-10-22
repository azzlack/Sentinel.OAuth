namespace Sentinel.OAuth.Core.Interfaces.Repositories
{
    using Sentinel.OAuth.Core.Interfaces.Models;
    using System.Collections.Generic;
    using System.Threading.Tasks;

    public interface IUserRepository
    {
        /// <summary>Gets the users.</summary>
        /// <returns>The users.</returns>
        Task<IEnumerable<IUser>> GetUsers();

        /// <summary>Gets a user.</summary>
        /// <param name="userId">Identifier for the user.</param>
        /// <returns>The user.</returns>
        Task<IUser> GetUser(string userId);
    }
}