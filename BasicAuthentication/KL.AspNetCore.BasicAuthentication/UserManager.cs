using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
#pragma warning disable CS1998 // Async method lacks 'await' operators and will run synchronously


namespace KL.AspNetCore.BasicAuthentication
{
    /// <summary>
    /// Scopes user manager
    /// </summary>
    public class UserManager : IUserManager
    {
        private Dictionary<string, UserInfo> Users { get; }

        /// <summary>
        /// User manager
        /// </summary>
        /// <param name="users">list of users</param>
        public UserManager(IEnumerable<UserInfo> users)
        {
            Users = users.ToDictionary(x => x.Id, y => y);
        }


        /// <summary>
        /// Authenticate
        /// </summary>
        /// <param name="userId"></param>
        /// <param name="pass"></param>
        /// <returns></returns>
        public async Task<IEnumerable<KeyValuePair<string, string>>> Authenticate(string userId, string pass)
        {
            if (!Users.TryGetValue(userId, out var userItem))
            {
                return null;
            }

            foreach (var key in userItem.Keys)
            {
                if (pass.HashPassword(key.Salt) == key.Hashed)
                {
                    var ret = new List<KeyValuePair<string, string>>()
                    {
                        new  KeyValuePair<string, string>(ClaimTypes.Name, userId)
                    };

                    if (userItem.Scopes != null)
                    {
                        ret.AddRange(userItem.Scopes.Select(x => new KeyValuePair<string, string>(BasicAuthenticationConstants.Scope, x)));
                    }
                    if (userItem.Roles != null)
                    {
                        ret.AddRange(userItem.Roles.Select(x => new KeyValuePair<string, string>(ClaimTypes.Role, x)));
                    }

                    return ret;
                }
            }
            return null;
        }
    }

    /// <summary>
    /// User 
    /// </summary>
    public class UserInfo
    {
        /// <summary>
        /// Keys
        /// </summary>
        [Required]
        public List<HashedKey> Keys { get; set; }

        /// <summary>
        /// Id
        /// </summary>
        [Required]
        public string Id { get; set; }

        /// <summary>
        /// Scopes
        /// </summary>
        [Required]
        public List<string> Scopes { get; set; }

        /// <summary>
        /// Roles
        /// </summary>
        [Required]
        public List<string> Roles { get; set; }
    }
}
