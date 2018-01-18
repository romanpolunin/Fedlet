using Microsoft.AspNetCore.Http;
using Newtonsoft.Json;

namespace Sun.Identity.Common
{
    /// <summary>
    /// Extensions for <see cref="T:Microsoft.AspNetCore.Http.ISession" /> that make life easier
    /// </summary>
    public static class SessionExtensions
    {
        /// <summary>
        /// Serializes any value to string and put it to <see cref="T:Microsoft.AspNetCore.Http.ISession" />
        /// </summary>
        /// <param name="session">Instance of <see cref="T:Microsoft.AspNetCore.Http.ISession" /></param>
        /// <param name="key">Session key</param>
        /// <param name="value">Value to put into session</param>
        public static void Set(this ISession session, string key, object value)
        {
            session.SetString(key, JsonConvert.SerializeObject(value));
        }


        /// <summary>
        /// Gets value from <see cref="T:Microsoft.AspNetCore.Http.ISession" /> and deserializes it
        /// </summary>
        /// <typeparam name="T">Type serialize to</typeparam>
        /// <param name="session">Instance of <see cref="T:Microsoft.AspNetCore.Http.ISession" /></param>
        /// <param name="key">Session key</param>
        /// <param name="defaultValue">Default value to return if key is not found</param>
        /// <returns></returns>
        public static T Get<T>(this ISession session, string key, T defaultValue = default(T))
        {
            string value = session.GetString(key);
            return value == null
                ? defaultValue
                : JsonConvert.DeserializeObject<T>(value);
        }
    }
}