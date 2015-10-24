namespace Sentinel.OAuth.Core.Interfaces.Identity
{
    using System.Collections.Generic;

    public interface ISentinelClaim
    {
        /// <summary>Gets the type.</summary>
        /// <value>The type.</value>
        string Type { get; }

        /// <summary>Gets the original type.</summary>
        /// <value>The original type.</value>
        string Alias { get; }

        /// <summary>Gets the value.</summary>
        /// <value>The value.</value>
        string Value { get; }
    }
}