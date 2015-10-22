namespace Sentinel.OAuth.Core.Models
{
    using Sentinel.OAuth.Core.Interfaces.Identity;
    using Sentinel.OAuth.Core.Interfaces.Models;

    public class TokenValidationResult<T> where T : IToken
    {
        /// <summary>Initializes a new instance of the <see cref="TokenValidationResult{T}" /> class.</summary>
        /// <param name="principal">The principal.</param>
        /// <param name="entity">The entity.</param>
        public TokenValidationResult(ISentinelPrincipal principal, T entity)
        {
            this.Principal = principal;
            this.Entity = entity;
        }

        /// <summary>Gets the principal.</summary>
        /// <value>The principal.</value>
        public ISentinelPrincipal Principal { get; }

        /// <summary>Gets the entity.</summary>
        /// <value>The entity.</value>
        public T Entity { get; }

        /// <summary>Determines if the result is valid.</summary>
        public bool IsValid => this.Principal != null && this.Principal.Identity.IsAuthenticated && this.Entity != null;
    }
}