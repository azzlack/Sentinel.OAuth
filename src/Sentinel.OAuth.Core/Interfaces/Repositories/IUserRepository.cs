namespace Sentinel.OAuth.Core.Interfaces.Repositories
{
    using System.Collections.Generic;
    using System.Threading.Tasks;

    using Sentinel.OAuth.Core.Interfaces.Models;

    public interface IUserRepository
    {
        /// <summary>Gets the users.</summary>
        /// <returns>The users.</returns>
        Task<IEnumerable<IUser>> GetUsers();

        /// <summary>Gets a user.</summary>
        /// <param name="userId">Identifier for the user.</param>
        /// <returns>The user.</returns>
        Task<IUser> GetUser(string userId);

        /// <summary>Updates the specified user.</summary>
        /// <typeparam name="T">The primary key type.</typeparam>
        /// <param name="id">The user identifier.</param>
        /// <param name="user">The user.</param>
        /// <returns>The updated user.</returns>
        Task<IUser> Update<T>(T id, IUser user);
    }
}