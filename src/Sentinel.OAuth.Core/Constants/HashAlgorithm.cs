namespace Sentinel.OAuth.Core.Constants
{
    public enum HashAlgorithm
    {
        /// <summary>The sha256 hash algorithm.</summary>
        SHA256 = 256,

        /// <summary>The sha384 hash algorithm.</summary>
        SHA384 = 384,

        /// <summary>The sha512 hash algorithm.</summary>
        SHA512 = 512,

        /// <summary>The PBKDF2 hash algorithm.</summary>
        PBKDF2 = 0
    }
}