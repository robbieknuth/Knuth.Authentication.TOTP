using Knuth.TOTP;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.ComponentModel.DataAnnotations;
using Xunit;

namespace Knuth.Authentication.TOTP.Test
{
    public sealed class TOTPTests
    {

        private const string Seed20Bytes = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        private const string Seed32Bytes = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA";
        private const string Seed64Bytes = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA";

        [Theory]
        [InlineData("1970-01-01T00:00:59Z", Seed20Bytes, "94287082", "sha1")]
        [InlineData("1970-01-01T00:00:59Z", Seed32Bytes, "46119246", "sha256")]
        [InlineData("1970-01-01T00:00:59Z", Seed64Bytes, "90693936", "sha512")]
        [InlineData("2005-03-18T01:58:29Z", Seed20Bytes, "07081804", "sha1")]
        [InlineData("2005-03-18T01:58:29Z", Seed32Bytes, "68084774", "sha256")]
        [InlineData("2005-03-18T01:58:29Z", Seed64Bytes, "25091201", "sha512")]
        [InlineData("2005-03-18T01:58:31Z", Seed20Bytes, "14050471", "sha1")]
        [InlineData("2005-03-18T01:58:31Z", Seed32Bytes, "67062674", "sha256")]
        [InlineData("2005-03-18T01:58:31Z", Seed64Bytes, "99943326", "sha512")]
        [InlineData("2009-02-13T23:31:30Z", Seed20Bytes, "89005924", "sha1")]
        [InlineData("2009-02-13T23:31:30Z", Seed32Bytes, "91819424", "sha256")]
        [InlineData("2009-02-13T23:31:30Z", Seed64Bytes, "93441116", "sha512")]
        [InlineData("2033-05-18T03:33:20Z", Seed20Bytes, "69279037", "sha1")]
        [InlineData("2033-05-18T03:33:20Z", Seed32Bytes, "90698825", "sha256")]
        [InlineData("2033-05-18T03:33:20Z", Seed64Bytes, "38618901", "sha512")]
        [InlineData("2603-10-11T11:33:20Z", Seed20Bytes, "65353130", "sha1")]
        [InlineData("2603-10-11T11:33:20Z", Seed32Bytes, "77737706", "sha256")]
        [InlineData("2603-10-11T11:33:20Z", Seed64Bytes, "47863826", "sha512")]
        public void TestsFromRFC6238(string dateTime, string key, string code, string algorithm)
        {
            var totpOptions = new TOTPOptions(digits: 8);
            var totpProvider = new ServiceCollection()
                .AddTOTP()
                .AddSingleton<ISystemClock>(new ExplicitSystemClock(dateTime))
                .BuildServiceProvider()
                .GetRequiredService<ITOTPProvider>();
            var result = totpProvider.GetCodes(algorithm, key, totpOptions);
            Assert.Equal(code, result.CurrentCode);
        }

        [Theory]
        [InlineData("2020-12-05T18:14:30Z", 30)]
        [InlineData("2020-12-05T18:14:37Z", 23)]
        [InlineData("2020-12-05T18:14:59Z", 1)]
        public void TestPeriodSecondHalf(string dateTime, int validFor)
        {
            var totpProvider = new ServiceCollection()
                .AddTOTP()
                .AddSingleton<ISystemClock>(new ExplicitSystemClock(dateTime))
                .BuildServiceProvider()
                .GetRequiredService<ITOTPProvider>();
            var result = totpProvider.GetCodes("sha1", "AABWY3DPEHPK3PXP");
            Assert.True(result.Matches("053248"));
            Assert.Equal("188204", result.CurrentCode);
            Assert.True(result.Matches("260636"));
            Assert.Equal(TimeSpan.FromSeconds(validFor), result.ValidFor);
        }

        [Theory]
        [InlineData("2020-12-05T18:17:00Z", 30)]
        [InlineData("2020-12-05T18:17:07Z", 23)]
        [InlineData("2020-12-05T18:17:29Z", 1)]
        public void TestPeriodFirstHalf(string dateTime, int validFor)
        {
            var totpProvider = new ServiceCollection()
                .AddTOTP()
                .AddSingleton<ISystemClock>(new ExplicitSystemClock(dateTime))
                .BuildServiceProvider()
                .GetRequiredService<ITOTPProvider>();
            var result = totpProvider.GetCodes("sha1", "AABWY3DPEHPK3PXP");
            Assert.True(result.Matches("651272"));
            Assert.Equal("065145", result.CurrentCode);
            Assert.True(result.Matches("822942"));
            Assert.Equal(TimeSpan.FromSeconds(validFor), result.ValidFor);
        }
    }
}
