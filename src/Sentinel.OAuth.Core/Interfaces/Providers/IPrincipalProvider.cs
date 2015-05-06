namespace Sentinel.OAuth.Core.Interfaces.Providers
{
    using Sentinel.OAuth.Core.Interfaces.Identity;

    public interface IPrincipalProvider
    {
        /// <summary>
        /// Gets an anonymous claims principal.
        /// </summary>
        /// <value>An anonymous claims principal.</value>
        ISentinelPrincipal Anonymous { get; }

        /// <summary>
        /// Gets the current claims principal.
        /// </summary>
        /// <value>The current claims principal.</value>
        ISentinelPrincipal Current { get; }

        /// <summary>
        /// Creates a claims principal with the specified authentication type and claims.
        /// </summary>
        /// <param name="authenticationType">Type of the authentication.</param>
        /// <param name="claims">The claims.</param>
        /// <returns>A claims principal.</returns>
        ISentinelPrincipal Create(string authenticationType, params ISentinelClaim[] claims);

        /// <summary>
        /// Encrypts the specified principal.
        /// </summary>
        /// <param name="principal">The principal.</param>
        /// <param name="key">The key.</param>
        /// <returns>The encrypted principal.</returns>
        string Encrypt(ISentinelPrincipal principal, string key);

        /// <summary>
        /// Decrypts the specified encrypted principal.
        /// </summary>
        /// <param name="ticket">The encrypted principal.</param>
        /// <param name="key">The key.</param>
        /// <returns>The principal.</returns>
        ISentinelPrincipal Decrypt(string ticket, string key);
    }
}