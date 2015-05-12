namespace Sentinel.OAuth.TokenManagers.RedisTokenRepository.Models
{
    using Sentinel.OAuth.Core.Interfaces.Models;

    using StackExchange.Redis;

    /// <summary>A wrapper for storing authorization codes in Redis.</summary>
    public class RedisAuthorizationCode : RedisClass<IAuthorizationCode>
    {
        /// <summary>The type key.</summary>
        public const string TypeKey = "RedisAuthorizationCode.Type";

        /// <summary>
        /// Initializes a new instance of the
        /// Sentinel.OAuth.TokenManagers.RedisTokenRepository.Models.RedisAuthorizationCode class.
        /// </summary>
        /// <param name="authorizationCode">The authorization code.</param>
        public RedisAuthorizationCode(IAuthorizationCode authorizationCode)
            : base(TypeKey, authorizationCode)
        {
        }

        /// <summary>
        /// Initializes a new instance of the
        /// Sentinel.OAuth.TokenManagers.RedisTokenRepository.Models.RedisAuthorizationCode class.
        /// </summary>
        /// <param name="hashEntries">The hash entries.</param>
        public RedisAuthorizationCode(HashEntry[] hashEntries)
            : base(TypeKey, hashEntries)
        {
        }
    }
}