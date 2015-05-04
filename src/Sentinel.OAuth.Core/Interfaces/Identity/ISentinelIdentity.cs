namespace Sentinel.OAuth.Core.Interfaces.Identity
{
    using System;
    using System.Collections.Generic;
    using System.IdentityModel.Claims;
    using System.Linq.Expressions;
    using System.Security.Principal;

    /// <summary>Defines basic funcitonality for an Identity object.</summary>
    public interface ISentinelIdentity : IIdentity
    {
        /// <summary>Gets or sets the claims.</summary>
        /// <value>The claims.</value>
        IEnumerable<ISentinelClaim> Claims { get; }
        
        /// <summary>Runs the specified expression against the claimset and returns true if it contains a claim matching the predicate.</summary>
        /// <param name="expression">The expression.</param>
        /// <returns><c>true</c> if the claim exists, <c>false</c> if not.</returns>
        bool HasClaim(Expression<Func<ISentinelClaim, bool>> expression);

        /// <summary>Adds a claim.</summary>
        /// <param name="type">The type.</param>
        /// <param name="value">The value.</param>
        void AddClaim(string type, string value);

        /// <summary>Adds a claim.</summary>
        /// <param name="claims">The claims</param>
        void AddClaim(params Claim[] claims);

        /// <summary>Adds a claim.</summary>
        /// <param name="claims">The claims.</param>
        void AddClaim(params ISentinelClaim[] claims);

        /// <summary>Removes the claim matching the expression.</summary>
        /// <param name="expression">The expression.</param>
        void RemoveClaim(Expression<Func<ISentinelClaim, bool>> expression);
    }
}