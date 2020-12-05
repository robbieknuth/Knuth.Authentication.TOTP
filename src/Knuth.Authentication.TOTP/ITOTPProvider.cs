using Knuth.Authentication.TOTP;

namespace Knuth.TOTP
{
    public interface ITOTPProvider
    {
        ITOTPResult GetCodes(string hashAlgorithm, string key, TOTPOptions options = null);

        ITOTPResult GetCodes(string hashAlgorithm, byte[] key, TOTPOptions options = null);
    }
}
