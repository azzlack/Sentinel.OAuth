namespace Sentinel.OAuth.Core.Interfaces.Identity
{
    using System.Security.Principal;

    /// <summary>Defines the basic functionality of a Principal object.</summary>
    public interface ISentinelPrincipal : IPrincipal
    {
        /// <summary>Gets the Sentinel identity.</summary>
        /// <value>The Sentinel identity.</value>
        new ISentinelIdentity Identity { get; }
    }
}