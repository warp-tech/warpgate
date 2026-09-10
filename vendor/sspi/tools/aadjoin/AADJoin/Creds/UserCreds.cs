using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AADJoin.Creds
{
    public class UserCreds
    {
        public string Username { get; set; }
        public string Password { get; set; }
        public string Domain { get; set; }

        public UserCreds(string username, string password, string domain)
        {
            if (username == null)
            {
                throw new ArgumentNullException(nameof(username));
            }

            if (password == null)
            {
                throw new ArgumentNullException(nameof(password));
            }

            if (domain == null)
            {
                throw new ArgumentNullException(nameof(domain));
            }

            Username = username;
            Password = password;
            Domain = domain;
        }
    }
}
