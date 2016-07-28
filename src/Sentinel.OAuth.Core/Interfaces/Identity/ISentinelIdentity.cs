namespace Sentinel.OAuth.Core.Interfaces.Identity
{
    using System;
    using System.Collections.Generic;
    using System.Security.Principal;

    /// <summary>Defines basic funcitonality for an Identity object.</summary>
    public interface ISentinelIdentity : IIdentity
    {
        /// <summary>Gets the claims.</summary>
        /// <value>The claims.</value>
        IEnumerable<ISentinelClaim> Claims { get; }

        /// <summary>Gets the roles.</summary>
        /// <value>The roles.</value>
        IEnumerable<string> Roles { get; }

        /// <summary>Gets the scopes.</summary>
        /// <value>The scopes.</value>
        IEnumerable<string> Scopes { get; }

        /// <summary>Determines whether the current identity belongs to the specified role.</summary>
        /// <param name="role">The name of the role for which to check membership.</param>
        /// <returns>
        /// true if the current identity is a member of the specified role; otherwise, false.
        /// </returns>
        bool IsInRole(string role);

        /// <summary>Runs the specified expression against the claimset and returns true if it contains a claim matching the predicate.</summary>
        /// <param name="expression">The expression.</param>
        /// <returns><c>true</c> if the claim exists, <c>false</c> if not.</returns>
        bool HasClaim(Func<ISentinelClaim, bool> expression);

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
        void RemoveClaim(Func<ISentinelClaim, bool> expression);

        /// <summary>Converts this object to a JSON string.</summary>
        /// <returns>This object as a JSON string.</returns>
        string ToJson();
    }
}