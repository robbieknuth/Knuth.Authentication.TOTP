﻿using System;

namespace Knuth.Authentication.TOTP
{
    public sealed class SystemClock : ISystemClock
    {
        public DateTime UtcNow => DateTime.UtcNow;
    }
}
