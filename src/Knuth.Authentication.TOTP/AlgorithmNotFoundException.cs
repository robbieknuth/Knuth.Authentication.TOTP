using System;

namespace Knuth.Authentication.TOTP
{
    public sealed class AlgorithmNotFoundException : Exception
    {
        internal AlgorithmNotFoundException(string algorithm)
            : base($"Algorithm for moniker '{algorithm}' was not found.") { }
    }
}
