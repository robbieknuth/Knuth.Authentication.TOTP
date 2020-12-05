using System;

namespace Knuth.Authentication.TOTP
{
    public interface ITOTPResult
    {
        string CurrentCode { get; }
        bool Matches(string code);
        TimeSpan ValidFor { get; }
    }
}
