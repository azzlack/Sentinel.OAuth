namespace Sentinel.OAuth.TokenManagers.RavenDbTokenRepository.Indexes
{
    using Raven.Client.Indexes;
    using Sentinel.OAuth.TokenManagers.RavenDbTokenRepository.Models.OAuth;
    using System.Linq;

    public class AuthorizationCodes_Ids : AbstractIndexCreationTask<RavenAuthorizationCode>
    {
        public AuthorizationCodes_Ids()
        {
            this.Map = codes => codes.Select(entity => new { });
        }
    }
}