using System.Collections.Generic;
using System.Threading.Tasks;

namespace KL.AspNetCore.BasicAuthentication
{
    /// <summary>
    /// User manager
    /// </summary>
    public interface IUserManager 
    {
        /// <summary>
        /// Get list of keys associated with an user
        /// </summary>
        /// <param name="userId">user Id</param>
        /// <param name="pass">pass</param>
        /// <returns>(keys, claims)</returns>
        Task<IEnumerable<KeyValuePair<string, string>>> AuthenticateAsync(string userId, string pass);
    }
}
