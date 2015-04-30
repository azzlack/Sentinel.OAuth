namespace Sentinel.OAuth.Implementation
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Security.Claims;

    using Newtonsoft.Json;

    using Sentinel.OAuth.Core.Interfaces.Providers;
    using Sentinel.OAuth.Core.Models.Identity;

    public class PrincipalProvider : IPrincipalProvider
    {
        /// <summary>The crypto provider.</summary>
        private readonly ICryptoProvider cryptoProvider;

        /// <summary>
        /// The current principal
        /// </summary>
        private readonly Lazy<ClaimsPrincipal> current = new Lazy<ClaimsPrincipal>(() => ClaimsPrincipal.Current);

        /// <summary>
        ///     Initializes a new instance of the Sentinel.OAuth.Implementation.PrincipalProvider
        ///     class.
        /// </summary>
        /// <param name="cryptoProvider">The crypto provider.</param>
        public PrincipalProvider(ICryptoProvider cryptoProvider)
        {
            if (cryptoProvider == null)
            {
                throw new ArgumentNullException("cryptoProvider");
            }

            this.cryptoProvider = cryptoProvider;
        }

        /// <summary>
        /// Creates an anonymous claims principal.
        /// </summary>
        /// <value>An anonymous claims principal.</value>
        public ClaimsPrincipal Anonymous
        {
            get
            {
                var identity = new ClaimsIdentity(new List<Claim>());

                return new ClaimsPrincipal(identity);
            }
        }

        /// <summary>
        /// Gets the current principal.
        /// </summary>
        /// <value>The current principal.</value>
        public ClaimsPrincipal Current
        {
            get
            {
                return this.current.Value;
            }
        }

        /// <summary>
        /// Creates a claims principal with the specified claims. Retrieves the authentication type from the list of claims.
        /// </summary>
        /// <param name="claims">The claims.</param>
        /// <returns>A claims principal.</returns>
        public ClaimsPrincipal Create(params Claim[] claims)
        {
            if (claims.All(x => x.Type == ClaimTypes.AuthenticationMethod))
            {
                throw new ArgumentException("No AuthenticationMethod claim found in claims", "claims");
            }

            return this.Create(claims.First(x => x.Type == ClaimTypes.AuthenticationMethod).Value, claims);
        }

        /// <summary>
        /// Creates a claims principal with the specified authentication type and claims.
        /// </summary>
        /// <param name="authenticationType">Type of the authentication.</param>
        /// <param name="claims">The claims.</param>
        /// <returns>A claims principal.</returns>
        public ClaimsPrincipal Create(string authenticationType, params Claim[] claims)
        {
            if (claims == null)
            {
                throw new ArgumentNullException("claims");
            }

            var c = claims.ToList();

            // Remove authentication method if it exist
            c.RemoveAll(x => x.Type == ClaimTypes.AuthenticationMethod);

            // Add proper authentication method
            c.Add(new Claim(ClaimTypes.AuthenticationMethod, authenticationType));

            return new ClaimsPrincipal(new ClaimsIdentity(c, authenticationType));
        }

        /// <summary>
        /// Adds the claims.
        /// </summary>
        /// <param name="principal">The principal.</param>
        /// <param name="newClaims">The claims.</param>
        public void AddClaims(ref ClaimsPrincipal principal, params Claim[] newClaims)
        {
            if (newClaims == null)
            {
                throw new ArgumentNullException("newClaims");
            }

            var c = principal.Claims.ToList();
            c.AddRange(newClaims);

            principal = new ClaimsPrincipal(new ClaimsIdentity(c, principal.Identity.AuthenticationType));
        }

        /// <summary>
        /// Creates role claims from the specified role names.
        /// </summary>
        /// <param name="roleNames">The role names.</param>
        /// <returns>A list of role claims.</returns>
        public IEnumerable<Claim> CreateRoles(string[] roleNames)
        {
            if (roleNames == null || !roleNames.Any())
            {
                return new Claim[] { };
            }

            return roleNames.Select(x => new Claim(ClaimTypes.Role, x));
        }

        /// <summary>
        /// Encrypts the specified principal.
        /// </summary>
        /// <param name="principal">The principal.</param>
        /// <param name="key">The key.</param>
        /// <returns>The encrypted principal.</returns>
        public string Encrypt(ClaimsPrincipal principal, string key)
        {
            var s = JsonConvert.SerializeObject(new JsonPrincipal(principal));

            return this.cryptoProvider.Encrypt(s, key);
        }

        /// <summary>
        /// Decrypts the specified encrypted principal.
        /// </summary>
        /// <param name="ticket">The encrypted principal.</param>
        /// <param name="key">The key.</param>
        /// <returns>The principal.</returns>
        public ClaimsPrincipal Decrypt(string ticket, string key)
        {
            var s = this.cryptoProvider.Decrypt(ticket, key);

            return JsonConvert.DeserializeObject<JsonPrincipal>(s);
        }
    }
}