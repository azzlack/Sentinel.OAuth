namespace Sentinel.OAuth.Core.Constants.Identity
{
    public class JwtClaimType
    {
        /// <summary>The subject claim type.</summary>
        public const string Subject = "sub";

        /// <summary>The issuer claim type.</summary>
        public const string Issuer = "iss";

        /// <summary>The audience claim type.</summary>
        public const string Audience = "aud";

        /// <summary>The expiration time claim type.</summary>
        public const string ExpirationTime = "exp";

        /// <summary>The valid from claim type.</summary>
        public const string NotBefore = "nbf";

        /// <summary>The issued at claim type.</summary>
        public const string IssuedAt = "iat";

        /// <summary>The JWT identifier claim type.</summary>
        public const string Id = "jti";

        /// <summary>The access token hash claim type.</summary>
        public const string AccessTokenHash = "at_hash";

        /// <summary>The authorization code hash claim type.</summary>
        public const string AuthorizationCodeHash = "c_hash";

        /// <summary>The first name claim type.</summary>
        public const string GivenName = "given_name";

        /// <summary>The last name claim type.</summary>
        public const string FamilyName = "family_name";

        /// <summary>The name claim type.</summary>
        public const string Name = "unique_name";
    }
}