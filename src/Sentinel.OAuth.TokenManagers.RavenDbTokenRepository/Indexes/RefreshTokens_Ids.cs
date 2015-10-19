namespace Sentinel.OAuth.TokenManagers.RavenDbTokenRepository.Indexes
{
    using Raven.Client.Indexes;
    using Sentinel.OAuth.TokenManagers.RavenDbTokenRepository.Models.OAuth;
    using System.Linq;

    public class RefreshTokens_Ids : AbstractIndexCreationTask<RavenRefreshToken>
    {
        public RefreshTokens_Ids()
        {
            this.Map = tokens => tokens.Select(entity => new { });
        }
    }
}