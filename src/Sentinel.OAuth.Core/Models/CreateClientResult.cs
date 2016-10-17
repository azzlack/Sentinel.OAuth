namespace Sentinel.OAuth.Core.Models
{
    using Sentinel.OAuth.Core.Interfaces.Models;

    public class CreateClientResult
    {
        public IClient Client { get; set; }

        public string ClientSecret { get; set; }

        public string PrivateKey { get; set; }
    }
}