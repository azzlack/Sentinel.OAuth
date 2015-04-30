namespace Sentinel.OAuth.Core.Constants.OAuth
{
    public class TokenFormat
    {
        /// <summary>
        ///     The default token format for the host.
        ///     For IIS this is <c>MachineKey</c>, for self-hosted sites it is <c>DPAPI</c>.
        /// </summary>
        public static string HostDefault = "HostDefault";

        /// <summary>
        ///     The sentinel token format.
        ///     
        /// </summary>
        public static string Sentinel = "Sentinel";
    }
}