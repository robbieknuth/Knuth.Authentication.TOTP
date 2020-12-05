using Knuth.Authentication.TOTP;

namespace Knuth.TOTP
{
    public interface ITOTPProvider
    {
        /// <summary>
        /// Gets TOTP codes for the previous period, current period, and next period.
        /// </summary>
        /// <param name="hashAlgorithm">The moniker for the hashing algorithm. See <see cref="IHashAlgorithmProvider.Moniker"/></param>
        /// <param name="key">The base32 encoded secret key that initializes the hash algorithm.</param>
        /// <param name="digits">The number of digits to produce. May be 6 to 8 inclusive.</param>
        /// <param name="period">The time period of the code. Must be 1 or larger.</param>
        /// <returns>A result containing TOTP codes.</returns>
        TOTPResult GetCodes(string hashAlgorithm, string key, int digits = 6, int period = 30);

        /// <summary>
        /// Gets TOTP codes for the previous period, current period, and next period.
        /// </summary>
        /// <param name="hashAlgorithm">The moniker for the hashing algorithm. See <see cref="IHashAlgorithmProvider.Moniker"/></param>
        /// <param name="key">The secret key that initializes the hash algorithm.</param>
        /// <param name="digits">The number of digits to produce. May be 6 to 8 inclusive.</param>
        /// <param name="period">The time period of the code. Must be 1 or larger.</param>
        /// <returns>A result containing TOTP codes.</returns>
        TOTPResult GetCodes(string hashAlgorithm, byte[] key, int digits = 6, int period = 30);
    }
}
