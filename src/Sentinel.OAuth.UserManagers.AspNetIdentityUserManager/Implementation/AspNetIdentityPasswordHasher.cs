namespace Sentinel.OAuth.UserManagers.AspNetIdentityUserManager.Implementation
{
    using Microsoft.AspNet.Identity;

    using Sentinel.OAuth.Core.Interfaces.Providers;

    public class AspNetIdentityPasswordHasher : PasswordHasher
    {
        private readonly IPasswordCryptoProvider passwordCryptoProvider;

        public AspNetIdentityPasswordHasher(IPasswordCryptoProvider passwordCryptoProvider)
        {
            this.passwordCryptoProvider = passwordCryptoProvider;
        }

        public override string HashPassword(string password)
        {
            return this.passwordCryptoProvider.CreateHash(password);
        }

        public override PasswordVerificationResult VerifyHashedPassword(string hashedPassword, string providedPassword)
        {
            return this.passwordCryptoProvider.ValidateHash(hashedPassword, providedPassword) ? PasswordVerificationResult.Success : PasswordVerificationResult.Failed;
        }
    }
}