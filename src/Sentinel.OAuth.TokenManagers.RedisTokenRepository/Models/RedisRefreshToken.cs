namespace Sentinel.OAuth.TokenManagers.RedisTokenRepository.Models
{
    using Sentinel.OAuth.Core.Interfaces.Models;

    using StackExchange.Redis;

    /// <summary>A wrapper for storing refresh tokens in Redis.</summary> 
    public class RedisRefreshToken : RedisClass<IRefreshToken>
    {
        /// <summary>The type key.</summary>
        public const string TypeKey = "RedisRefreshToken.Type";

        /// <summary>
        /// Initializes a new instance of the
        /// Sentinel.OAuth.TokenManagers.RedisTokenRepository.Models.RedisRefreshToken class.
        /// </summary>
        /// <param name="refreshToken">The refresh token.</param>
        public RedisRefreshToken(IRefreshToken refreshToken)
            : base(TypeKey, refreshToken)
        {
        }

        /// <summary>
        /// Initializes a new instance of the
        /// Sentinel.OAuth.TokenManagers.RedisTokenRepository.Models.RedisRefreshToken class.
        /// </summary>
        /// <param name="hashEntries">The hash entries.</param>
        public RedisRefreshToken(HashEntry[] hashEntries)
            : base(TypeKey, hashEntries)
        {
        }
    }
}