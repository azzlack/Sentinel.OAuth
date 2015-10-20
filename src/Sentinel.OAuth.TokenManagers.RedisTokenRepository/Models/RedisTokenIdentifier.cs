namespace Sentinel.OAuth.TokenManagers.RedisTokenRepository.Models
{
    public class RedisTokenIdentifier
    {
        public string Key { get; set; }

        public string ClientId { get; set; }

        public string RedirectUri { get; set; }

        public string Subject { get; set; }
    }
}
