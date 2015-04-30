namespace Sentinel.OAuth.Core.Interfaces.Providers
{
    using System.Collections.Generic;
    using System.Security.Claims;

    public interface IPrincipalProvider
    {
        /// <summary>
        /// Gets an anonymous claims principal.
        /// </summary>
        /// <value>An anonymous claims principal.</value>
        ClaimsPrincipal Anonymous { get; }

        /// <summary>
        /// Gets the current claims principal.
        /// </summary>
        /// <value>The current claims principal.</value>
        ClaimsPrincipal Current { get; }

        /// <summary>
        /// Creates a claims principal with the specified claims. Retrieves the authentication type from the list of claims.
        /// </summary>
        /// <param name="claims">The claims.</param>
        /// <returns>A claims principal.</returns>
        ClaimsPrincipal Create(params Claim[] claims);

        /// <summary>
        /// Creates a claims principal with the specified authentication type and claims.
        /// </summary>
        /// <param name="authenticationType">Type of the authentication.</param>
        /// <param name="claims">The claims.</param>
        /// <returns>A claims principal.</returns>
        ClaimsPrincipal Create(string authenticationType, params Claim[] claims);

        /// <summary>
        /// Adds the claims.
        /// </summary>
        /// <param name="principal">The principal.</param>
        /// <param name="newClaims">The claims.</param>
        void AddClaims(ref ClaimsPrincipal principal, params Claim[] newClaims);

        /// <summary>
        /// Creates role claims from the specified role names.
        /// </summary>
        /// <param name="roleNames">The role names.</param>
        /// <returns>A list of role claims.</returns>
        IEnumerable<Claim> CreateRoles(string[] roleNames);

        /// <summary>
        /// Encrypts the specified principal.
        /// </summary>
        /// <param name="principal">The principal.</param>
        /// <param name="key">The key.</param>
        /// <returns>The encrypted principal.</returns>
        string Encrypt(ClaimsPrincipal principal, string key);

        /// <summary>
        /// Decrypts the specified encrypted principal.
        /// </summary>
        /// <param name="ticket">The encrypted principal.</param>
        /// <param name="key">The key.</param>
        /// <returns>The principal.</returns>
        ClaimsPrincipal Decrypt(string ticket, string key);
    }
}