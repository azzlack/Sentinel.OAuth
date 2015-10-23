namespace Sentinel.OAuth.Core.Models.OAuth.Http
{
    using Newtonsoft.Json;
    using Sentinel.OAuth.Core.Constants.Identity;
    using Sentinel.OAuth.Core.Converters;
    using Sentinel.OAuth.Core.Interfaces.Identity;
    using System;
    using System.Collections.Generic;
    using System.Collections.ObjectModel;
    using System.Linq;

    [JsonConverter(typeof(IdentityResponseJsonConverter))]
    public class IdentityResponse : Collection<KeyValuePair<string, string>>
    {
        /// <summary>Initializes a new instance of the <see cref="IdentityResponse" /> class.</summary>
        /// <param name="claims">A variable-length parameters list containing claims.</param>
        public IdentityResponse(IEnumerable<KeyValuePair<string, string>> claims)
        {
            foreach (var claim in claims)
            {
                this.Add(new KeyValuePair<string, string>(claim.Key, claim.Value));
            }
        }

        /// <summary>Initializes a new instance of the <see cref="IdentityResponse" /> class.</summary>
        /// <param name="identity">The identity.</param>
        public IdentityResponse(ISentinelIdentity identity)
        {
            foreach (var claim in identity.Claims)
            {
                this.Add(new KeyValuePair<string, string>(claim.Type, claim.Value));
            }
        }

        /// <summary>Initializes a new instance of the <see cref="IdentityResponse" /> class.</summary>
        /// <param name="claims">A variable-length parameters list containing claims.</param>
        public IdentityResponse(params ISentinelClaim[] claims)
        {
            foreach (var claim in claims)
            {
                this.Add(new KeyValuePair<string, string>(claim.Type, claim.Value));
            }
        }

        /// <summary>Gets the identifier.</summary>
        /// <value>The identifier.</value>
        public string Id
        {
            get
            {
                var claim = this.FirstOrDefault(x => x.Key == "jti" || x.Key == ClaimType.Id);

                return claim.Value;
            }
        }

        /// <summary>Gets the issuer.</summary>
        /// <value>The issuer.</value>
        public string Issuer
        {
            get
            {
                var claim = this.FirstOrDefault(x => x.Key == "iss" || x.Key == ClaimType.Issuer);

                return claim.Value;
            }
        }

        /// <summary>Gets the subject.</summary>
        /// <value>The subject.</value>
        public string Subject
        {
            get
            {
                var claim = this.FirstOrDefault(x => x.Key == "sub" || x.Key == ClaimType.Name);

                return claim.Value;
            }
        }

        /// <summary>Gets the audience.</summary>
        /// <value>The audience.</value>
        public string Audience
        {
            get
            {
                var claim = this.FirstOrDefault(x => x.Key == "aud" || x.Key == ClaimType.RedirectUri);

                return claim.Value;
            }
        }

        /// <summary>Gets the expiration time.</summary>
        /// <value>The expiration time.</value>
        public DateTimeOffset ExpirationTime
        {
            get
            {
                DateTimeOffset dt;
                var claim = this.FirstOrDefault(x => x.Key == "exp" || x.Key == ClaimType.Expiration);

                if (DateTimeOffset.TryParse(claim.Value, out dt))
                {
                    return dt;
                }

                return DateTimeOffset.MinValue;
            }
        }

        /// <summary>Gets the valid from time.</summary>
        /// <value>The valid from time.</value>
        public DateTimeOffset ValidFrom
        {
            get
            {
                DateTimeOffset dt;
                var claim = this.FirstOrDefault(x => x.Key == "nbf" || x.Key == ClaimType.ValidFrom);

                if (DateTimeOffset.TryParse(claim.Value, out dt))
                {
                    return dt;
                }

                return DateTimeOffset.MinValue;
            }
        }

        /// <summary>Gets the created time.</summary>
        /// <value>The created time.</value>
        public DateTimeOffset Created
        {
            get
            {
                DateTimeOffset dt;
                var claim = this.FirstOrDefault(x => x.Key == "iat" || x.Key == ClaimType.AuthenticationInstant);

                if (DateTimeOffset.TryParse(claim.Value, out dt))
                {
                    return dt;
                }

                return DateTimeOffset.MinValue;
            }
        }
    }
}