using Knuth.Authentication.TOTP;
using Knuth.TOTP;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Threading;
using System.Threading.Tasks;

namespace TOTP
{
    internal static class Program
    {
        static async Task<int> Main(string[] args)
        {
            if (args.Length != 2)
            {
                Console.WriteLine("Usage: TOTP.exe <algorithm> <key>");
                return 1;
            }

            var totp = new ServiceCollection()
                .AddTOTP()
                .BuildServiceProvider()
                .GetRequiredService<ITOTPProvider>();

            using var cts = new CancellationTokenSource();
            Console.CancelKeyPress += (sender, eventArgs) =>
            {
                cts.Cancel();
                eventArgs.Cancel = true;
            };

            try
            {
                while (!cts.Token.IsCancellationRequested)
                {
                    var codes = totp.GetCodes(args[0], args[1]);
                    Console.WriteLine($"Current: {codes.CurrentCode} (Previous: {codes.PreviousCode}, Next: {codes.NextCode})");
                    Console.WriteLine($"    Next refresh in {(int)codes.ValidFor.TotalSeconds} seconds.");
                    await Task.Delay(codes.ValidFor, cts.Token);
                }
            }
            catch (OperationCanceledException) when (cts.Token.IsCancellationRequested) { }
            catch (AlgorithmNotFoundException e)
            {
                Console.Error.Write(e.Message);
                return 1;
            }
            catch (FormatException e)
            {
                Console.Error.WriteLine(e.Message);
                return 1;
            }
            catch (Exception e)
            {
                Console.Error.WriteLine("Unexpected exception encountered.");
                Console.Error.WriteLine(e);
                return 1;
            }

            return 0;
        }
    }
}
