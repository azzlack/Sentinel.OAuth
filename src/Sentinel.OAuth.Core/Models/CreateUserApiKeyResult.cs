namespace Sentinel.OAuth.Core.Models
{
    using Sentinel.OAuth.Core.Interfaces.Models;

    public class CreateUserApiKeyResult
    {
        public IUserApiKey ApiKey { get; set; }

        public string PrivateKey { get; set; }
    }
}