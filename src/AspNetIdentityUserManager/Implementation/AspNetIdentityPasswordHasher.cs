namespace Sentinel.OAuth.UserManagers.AspNetIdentityUserManager.Implementation
{
    using Microsoft.AspNet.Identity;

    using Sentinel.OAuth.Core.Interfaces.Providers;

    public class AspNetIdentityPasswordHasher : PasswordHasher
    {
        private readonly ICryptoProvider cryptoProvider;

        public AspNetIdentityPasswordHasher(ICryptoProvider cryptoProvider)
        {
            this.cryptoProvider = cryptoProvider;
        }

        public override string HashPassword(string password)
        {
            return this.cryptoProvider.CreateHash(password);
        }

        public override PasswordVerificationResult VerifyHashedPassword(string hashedPassword, string providedPassword)
        {
            return this.cryptoProvider.ValidateHash(hashedPassword, providedPassword) ? PasswordVerificationResult.Success : PasswordVerificationResult.Failed;
        }
    }
}