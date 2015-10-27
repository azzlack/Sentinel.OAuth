namespace Sentinel.OAuth.Core.Models.Tokens
{
    using Sentinel.OAuth.Core.Extensions;
    using System;

    public class JsonWebTokenPayload : JsonWebTokenComponent
    {
        /// <summary>The identifier.</summary>
        public string Id => this["jti"]?.ToString();

        /// <summary>The audience.</summary>
        public string Audience => this["aud"]?.ToString();

        /// <summary>Gets the issuer.</summary>
        /// <value>The issuer.</value>
        public Uri Issuer
        {
            get
            {
                var iss = this["iss"];

                if (iss == null)
                {
                    return null;
                }

                return new Uri(iss.ToString());
            }
        }

        /// <summary>The subject.</summary>
        public string Subject => this["sub"]?.ToString();

        /// <summary>The access token hash.</summary>
        public string AccessTokenHash => this["at_hash"]?.ToString();

        /// <summary>The authorization code hash.</summary>
        public string AuthorizationCodeHash => this["c_hash"]?.ToString();

        /// <summary>Gets the valid from time.</summary>
        /// <value>The valid from time.</value>
        public DateTimeOffset ValidFrom
        {
            get
            {
                var nbf = this["nbf"];

                if (nbf == null)
                {
                    return DateTimeOffset.MinValue;
                }

                long ticks;
                if (long.TryParse(nbf.ToString(), out ticks))
                {
                    return ticks.ToDateTimeOffset();
                }

                return DateTimeOffset.MinValue;
            }
        }

        /// <summary>Gets the expire time.</summary>
        /// <value>The expire time.</value>
        public DateTimeOffset Expires
        {
            get
            {
                var exp = this["exp"];

                if (exp == null)
                {
                    return DateTimeOffset.MinValue;
                }

                long ticks;
                if (long.TryParse(exp.ToString(), out ticks))
                {
                    return ticks.ToDateTimeOffset();
                }

                return DateTimeOffset.MinValue;
            }
        }
    }
}