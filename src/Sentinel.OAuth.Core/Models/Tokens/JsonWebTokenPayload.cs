namespace Sentinel.OAuth.Core.Models.Tokens
{
    using Sentinel.OAuth.Core.Extensions;
    using System;

    public class JsonWebTokenPayload : JsonWebTokenComponent
    {
        /// <summary>The identifier.</summary>
        public string Id => this["jti"];

        /// <summary>The audience.</summary>
        public string Audience => this["aud"];

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

                return new Uri(iss);
            }
        }

        /// <summary>The subject.</summary>
        public string Subject => this["sub"];

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
                if (long.TryParse(nbf, out ticks))
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
                if (long.TryParse(exp, out ticks))
                {
                    return ticks.ToDateTimeOffset();
                }

                return DateTimeOffset.MinValue;
            }
        }
    }
}