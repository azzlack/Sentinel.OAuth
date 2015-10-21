namespace Sentinel.OAuth.Core.Models
{
    using Sentinel.OAuth.Core.Interfaces.Models;

    public class TokenCreationResult<T> where T : IToken
    {
        /// <summary>Initializes a new instance of the Sentinel.OAuth.Core.Models.TokenCreationResult class.</summary>
        /// <param name="token">The token.</param>
        /// <param name="entity">The entity.</param>
        public TokenCreationResult(string token, T entity)
        {
            this.Token = token;
            this.Entity = entity;
        }

        /// <summary>Gets the token.</summary>
        /// <value>The token.</value>
        public string Token { get; }

        /// <summary>Gets the entity.</summary>
        /// <value>The entity.</value>
        public T Entity { get; }
    }
}