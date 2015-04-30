namespace Sentinel.OAuth.Implementation
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Security.Claims;
    using System.Security.Cryptography;
    using System.Text;

    using Newtonsoft.Json;

    using Sentinel.OAuth.Core.Interfaces.Providers;
    using Sentinel.OAuth.Core.Models.Identity;

    public class PrincipalProvider : IPrincipalProvider
    {
        /// <summary>
        /// The current principal
        /// </summary>
        private readonly Lazy<ClaimsPrincipal> current = new Lazy<ClaimsPrincipal>(() => ClaimsPrincipal.Current);

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

            byte[] encrypted;

            using (var rijAlg = new RijndaelManaged() { Key = Encoding.UTF8.GetBytes(key), IV = Encoding.UTF8.GetBytes("@1B2c3D4e5F6g7H8") })
            {
                var encryptor = rijAlg.CreateEncryptor(rijAlg.Key, rijAlg.IV);

                using (var msEncrypt = new MemoryStream())
                {
                    using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (var swEncrypt = new StreamWriter(csEncrypt))
                        {
                            swEncrypt.Write(s);
                        }

                        encrypted = msEncrypt.ToArray();
                    }
                }
            }

            return Convert.ToBase64String(encrypted);
        }

        /// <summary>
        /// Decrypts the specified encrypted principal.
        /// </summary>
        /// <param name="ticket">The encrypted principal.</param>
        /// <param name="key">The key.</param>
        /// <returns>The principal.</returns>
        public ClaimsPrincipal Decrypt(string ticket, string key)
        {
            string s;

            using (var rijAlg = new RijndaelManaged() { Key = Encoding.UTF8.GetBytes(key), IV = Encoding.UTF8.GetBytes("@1B2c3D4e5F6g7H8") })
            {
                var decryptor = rijAlg.CreateDecryptor(rijAlg.Key, rijAlg.IV);

                using (var msDecrypt = new MemoryStream(Convert.FromBase64String(ticket)))
                {
                    using (var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (var srDecrypt = new StreamReader(csDecrypt))
                        {
                            s = srDecrypt.ReadToEnd();
                        }
                    }
                }
            }

            return JsonConvert.DeserializeObject<JsonPrincipal>(s);
        }
    }
}