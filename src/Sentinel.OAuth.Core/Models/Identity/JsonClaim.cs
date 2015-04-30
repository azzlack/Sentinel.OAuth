namespace Sentinel.OAuth.Core.Models.Identity
{
    using System;
    using System.Diagnostics;
    using System.Security.Claims;

    /// <summary>A JSON-serializable claim.</summary>
    [DebuggerDisplay("Type: {Type}, Value: {Value}, ValueType: {ValueType}, Issuer: {Issuer}, OriginalIssuer: {OriginalIssuer}")]
    public class JsonClaim : IComparable, IComparable<JsonClaim>
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="JsonClaim"/> class.
        /// </summary>
        public JsonClaim()
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="JsonClaim"/> class.
        /// </summary>
        /// <param name="claim">The claim.</param>
        public JsonClaim(Claim claim)
        {
            this.Type = claim.Type;
            this.Value = claim.Value;
            this.ValueType = claim.ValueType;
            this.Issuer = claim.Issuer;
            this.OriginalIssuer = claim.OriginalIssuer;
        }

        /// <summary>
        /// Gets or sets the type.
        /// </summary>
        /// <value>The type.</value>
        public string Type { get; set; }

        /// <summary>
        /// Gets or sets the value.
        /// </summary>
        /// <value>The value.</value>
        public string Value { get; set; }

        /// <summary>
        /// Gets or sets the type of the value.
        /// </summary>
        /// <value>The type of the value.</value>
        public string ValueType { get; set; }

        /// <summary>
        /// Gets or sets the issuer.
        /// </summary>
        /// <value>The issuer.</value>
        public string Issuer { get; set; }

        /// <summary>
        /// Gets or sets the original issuer.
        /// </summary>
        /// <value>The original issuer.</value>
        public string OriginalIssuer { get; set; }

        /// <summary>
        /// Performs an implicit conversion from <see cref="JsonClaim"/> to <see cref="Claim"/>.
        /// </summary>
        /// <param name="m">The m.</param>
        /// <returns>The result of the conversion.</returns>
        public static implicit operator Claim(JsonClaim m)
        {
            return new Claim(m.Type, m.Value, m.ValueType, m.Issuer, m.OriginalIssuer);
        }

        /// <summary>
        /// Performs an explicit conversion from <see cref="Claim"/> to <see cref="JsonClaim"/>.
        /// </summary>
        /// <param name="m">The m.</param>
        /// <returns>The result of the conversion.</returns>
        public static explicit operator JsonClaim(Claim m)
        {
            return new JsonClaim(m);
        }

        /// <summary>
        /// Compares the current instance with another object of the same type and returns an integer that indicates whether the current instance precedes, follows, or occurs in the same position in the sort order as the other object.
        /// </summary>
        /// <param name="other">The other object.</param>
        /// <returns>A value that indicates the relative order of the objects being compared. The return value has these meanings: Value Meaning Less than zero This instance precedes <paramref name="obj" /> in the sort order. Zero This instance occurs in the same position in the sort order as <paramref name="obj" />. Greater than zero This instance follows <paramref name="obj" /> in the sort order.</returns>
        public int CompareTo(JsonClaim other)
        {
            if (other == null)
            {
                return 1;
            }

            if (other.Type == this.Type
                && other.Value == this.Value
                && other.ValueType == this.ValueType
                && other.Issuer == this.Issuer
                && other.OriginalIssuer == this.OriginalIssuer)
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

            var claim = obj as JsonClaim;

            if (claim != null)
            {
                return this.CompareTo(claim);
            }

            return -1;
        }

        /// <summary>
        /// Returns a <see cref="System.String" /> that represents this instance.
        /// </summary>
        /// <returns>A <see cref="System.String" /> that represents this instance.</returns>
        public override string ToString()
        {
            return string.Format("Type: {0}, Value: {1}, ValueType: {2}, Issuer: {3}, OriginalIssuer: {4}", this.Type, this.Value, this.ValueType, this.Issuer, this.OriginalIssuer);
        }
    }
}