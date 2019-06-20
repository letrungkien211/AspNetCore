using System;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;

namespace KL.AspNetCore.BasicAuthentication
{
    /// <summary>
    /// 
    /// </summary>
    internal static class Extensions
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="authorizationHeaderParameter"></param>
        /// <returns></returns>
        internal static (string, string) AuthorizationParameterToBasicAuth(this string authorizationHeaderParameter)
        {
            try
            {
                var splits = Encoding.UTF8.GetString(Convert.FromBase64String(authorizationHeaderParameter)).Split(':');
                if (splits.Length == 2)
                    return (splits[0], splits[1]);
                else
                {
                    return (null, null);
                }
            }
            catch
            {
                return (null, null);
            }
        }

        /// <summary>
        /// Test hash password
        /// </summary>
        /// <param name="pass"></param>
        /// <param name="salt"></param>
        /// <returns></returns>
        internal static string HashPassword(this string pass, string salt)
        {
            return Convert.ToBase64String(KeyDerivation.Pbkdf2(
                        password: pass,
                        salt: Convert.FromBase64String(salt),
                        prf: KeyDerivationPrf.HMACSHA1,
                        iterationCount: 10000,
                        numBytesRequested: 256 / 8));
        }

        /// <summary>
        /// Hash password
        /// </summary>
        /// <param name="pass"></param>
        /// <returns></returns>
        internal static (string, string) HashPassword(this string pass)
        {
            byte[] saltByte = new byte[128 / 8];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(saltByte);
            }

            var salt = Convert.ToBase64String(saltByte);

            return (salt, pass.HashPassword(salt));
        }
    }
}
