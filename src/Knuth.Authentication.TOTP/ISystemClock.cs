using System;

namespace Knuth.Authentication.TOTP
{
    public interface ISystemClock
    {
        DateTime UtcNow { get; }
    }
}
