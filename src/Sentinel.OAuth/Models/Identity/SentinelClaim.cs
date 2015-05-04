namespace Sentinel.OAuth.Models.Identity
{
    using System;
    using System.Diagnostics;
    using System.IdentityModel.Claims;

    using Newtonsoft.Json;

    using Sentinel.OAuth.Core.Interfaces.Identity;

    /// <summary>A JSON-serializable claim.</summary>
    [DebuggerDisplay("Type: {Type}, Value: {Value}")]
    public class SentinelClaim : ISentinelClaim, IComparable, IComparable<SentinelClaim>
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="SentinelClaim"/> class.
        /// </summary>
        /// <param name="claim">The claim.</param>
        public SentinelClaim(Claim claim)
        {
            this.Type = claim.ClaimType;
            this.Value = claim.Resource.ToString();
        }

        /// <summary>
        ///     Initializes a new instance of the Sentinel.OAuth.Core.Models.Identity.JsonClaim class.
        /// </summary>
        /// <param name="type">The type.</param>
        /// <param name="value">The value.</param>
        public SentinelClaim(string type, string value)
        {
            this.Type = type;
            this.Value = value;
        }

        /// <summary>
        /// Gets or sets the type.
        /// </summary>
        /// <value>The type.</value>
        [JsonProperty]
        public string Type { get; private set; }

        /// <summary>
        /// Gets or sets the value.
        /// </summary>
        /// <value>The value.</value>
        [JsonProperty]
        public string Value { get; private set; }

        /// <summary>
        /// Performs an implicit conversion from <see cref="SentinelClaim"/> to <see cref="Claim"/>.
        /// </summary>
        /// <param name="m">The m.</param>
        /// <returns>The result of the conversion.</returns>
        public static implicit operator Claim(SentinelClaim m)
        {
            return new Claim(m.Type, m.Value, Rights.PossessProperty);
        }

        /// <summary>
        /// Performs an explicit conversion from <see cref="Claim"/> to <see cref="SentinelClaim"/>.
        /// </summary>
        /// <param name="m">The m.</param>
        /// <returns>The result of the conversion.</returns>
        public static explicit operator SentinelClaim(Claim m)
        {
            return new SentinelClaim(m);
        }

        /// <summary>
        /// Compares the current instance with another object of the same type and returns an integer that indicates whether the current instance precedes, follows, or occurs in the same position in the sort order as the other object.
        /// </summary>
        /// <param name="other">The other object.</param>
        /// <returns>A value that indicates the relative order of the objects being compared. The return value has these meanings: Value Meaning Less than zero This instance precedes <paramref name="obj" /> in the sort order. Zero This instance occurs in the same position in the sort order as <paramref name="obj" />. Greater than zero This instance follows <paramref name="obj" /> in the sort order.</returns>
        public int CompareTo(SentinelClaim other)
        {
            if (other == null)
            {
                return 1;
            }

            if (other.Type == this.Type
                && other.Value == this.Value)
            {
                return 0;
            }

            return -1;
        }

        /// <summary>
        /// Compares the current instance with another object of the same type and returns an integer that indicates whether the current instance precedes, follows, or occurs in the same position in the sort order as the other object.
        /// </summary>
        /// <param name="obj">An object to compare with this instance.</param>
        /// <returns>A value that indicates the relative order of the objects being compared. The return value has these meanings: Value Meaning Less than zero This instance precedes <paramref name="obj" /> in the sort order. Zero This instance occurs in the same position in the sort order as <paramref name="obj" />. Greater than zero This instance follows <paramref name="obj" /> in the sort order.</returns>
        public int CompareTo(object obj)
        {
            if (obj == null)
            {
                return 1;
            }

            var claim = obj as SentinelClaim;

            if (claim != null)
            {
                return this.CompareTo(claim);
            }

            return -1;
        }

        /// <summary>
        /// Returns a <see cref="string" /> that represents this instance.
        /// </summary>
        /// <returns>A <see cref="string" /> that represents this instance.</returns>
        public override string ToString()
        {
            return string.Format("Type: {0}, Value: {1}", this.Type, this.Value);
        }
    }
}