namespace Sentinel.OAuth.Core.Interfaces.Identity
{
    using System;
    using System.Collections.Generic;
    using System.Linq.Expressions;
    using System.Security.Principal;

    /// <summary>Defines basic funcitonality for an Identity object.</summary>
    public interface ISentinelIdentity : IIdentity
    {
        /// <summary>Gets the claims.</summary>
        /// <value>The claims.</value>
        IEnumerable<ISentinelClaim> Claims { get; }
        
        /// <summary>Runs the specified expression against the claimset and returns true if it contains a claim matching the predicate.</summary>
        /// <param name="expression">The expression.</param>
        /// <returns><c>true</c> if the claim exists, <c>false</c> if not.</returns>
        bool HasClaim(Expression<Func<ISentinelClaim, bool>> expression);

        /// <summary>
        /// Checks if this identity contains any claims matching the specified type and value.
        /// </summary>
        /// <param name="type">The type.</param>
        /// <param name="value">The value.</param>
        /// <returns><c>true</c> if the claim exists, <c>false</c> if not.</returns>
        bool HasClaim(string type, string value);

        /// <summary>Adds a claim.</summary>
        /// <param name="type">The type.</param>
        /// <param name="value">The value.</param>
        void AddClaim(string type, string value);

        /// <summary>Adds a claim.</summary>
        /// <param name="claims">The claims.</param>
        void AddClaim(params ISentinelClaim[] claims);

        /// <summary>Removes the claim matching the expression.</summary>
        /// <param name="expression">The expression.</param>
        void RemoveClaim(Expression<Func<ISentinelClaim, bool>> expression);
    }
}