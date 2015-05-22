using System.Net.Mail;

namespace NaclKeys.Helper
{
    public static class StringHelper
    {
        /// <summary>
        ///     Validate an email address.
        /// </summary>
        /// <param name="email"></param>
        /// <returns></returns>
        public static bool IsValidEmail(string email)
        {
            try
            {
                var addr = new MailAddress(email);
                return addr.Address == email;
            }
            catch
            {
                return false;
            }
        }
    }
}