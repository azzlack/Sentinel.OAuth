namespace Sentinel.OAuth.Core.Interfaces.Identity
{
    public interface ISentinelClaim
    {
        /// <summary>Gets the type.</summary>
        /// <value>The type.</value>
        string Type { get; }
        
        /// <summary>Gets the value.</summary>
        /// <value>The value.</value>
        string Value { get; }
    }
}