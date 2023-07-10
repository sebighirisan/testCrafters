using System;
using System.Security.Cryptography;

namespace TestCraftersCode
{
    class Program

    {

        static void Main(string[] args)
        {
            string userId = "your_user_id";
            DateTime dateTime = DateTime.Now;

            string otp =OneTimePasswordGenerator.GenerateOTP(userId, dateTime);

            Console.WriteLine("Generated OTP: " + otp);
        }
        public class OneTimePasswordGenerator
        {
            private const int TokenDurationSeconds = 30;

            public static string GenerateOTP(string userId, DateTime dateTime)
            {
                // Replace this with your own secret key for better security.
                string secretKey = "ReplaceWithYourSecretKey";

                // Convert the secret key to bytes.
                byte[] keyBytes = System.Text.Encoding.ASCII.GetBytes(secretKey);

                // Convert the DateTime to Unix time (seconds since January 1, 1970).
                long unixTime = ((DateTimeOffset)dateTime).ToUnixTimeSeconds();

                // Calculate the number of time intervals that have passed since the Unix epoch.
                long timeInterval = unixTime / TokenDurationSeconds;

                // Convert the time interval to bytes.
                byte[] timeIntervalBytes = BitConverter.GetBytes(timeInterval);

                // Make sure the time interval bytes are in big-endian order (network byte order).
                if (BitConverter.IsLittleEndian)
                    Array.Reverse(timeIntervalBytes);

                // Create a new instance of HMACSHA1 using the secret key.
                using (var hmac = new HMACSHA1(keyBytes))
                {
                    // Compute the hash of the time interval bytes.
                    byte[] hash = hmac.ComputeHash(timeIntervalBytes);

                    // Get the offset value from the last 4 bits of the hash to generate the OTP index.
                    int offset = hash[hash.Length - 1] & 0x0F;

                    // Get the 4 bytes at the offset to create the dynamic binary code.
                    int binaryCode = ((hash[offset] & 0x7F) << 24) | ((hash[offset + 1] & 0xFF) << 16) | ((hash[offset + 2] & 0xFF) << 8) | (hash[offset + 3] & 0xFF);

                    // Convert the binary code to a 6-digit OTP by using modulo 1,000,000.
                    int otp = binaryCode % 1000000;

                    // Pad the OTP with leading zeros if necessary.
                    return otp.ToString("D6");
                }
            }
        }
    }
}

