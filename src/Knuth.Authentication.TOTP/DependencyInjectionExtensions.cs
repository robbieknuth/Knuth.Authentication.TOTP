using Knuth.Authentication.TOTP;
using Knuth.TOTP;

namespace Microsoft.Extensions.DependencyInjection
{
    public static class DependencyInjectionExtensions
    {
        public static IServiceCollection AddTOTP(this IServiceCollection services)
        {
            return services
                .AddSingleton<ITOTPProvider, TOTPProvider>()
                .AddSingleton<ISystemClock, SystemClock>()
                .AddSingleton<IHashAlgorithmProvider, HMACSHA1AlgorithmProvider>()
                .AddSingleton<IHashAlgorithmProvider, HMACSHA256AlgorithmProvider>()
                .AddSingleton<IHashAlgorithmProvider, HMACSHA512AlgorithmProvider>();
        }
    }
}
