using Microsoft.AspNetCore.Http;

namespace Sun.Identity.Common
{
    /// <summary>
    /// Extension that implements functionality of <see cref="P:System.Web.HttpRequest.Items" />
    /// </summary>
    public static class HttpRequestExtensions
    {
        /// <summary>Gets the specified object from the <see cref="P:Microsoft.AspNetCore.Http.HttpRequest.Query" />,
        /// <see cref="P:Microsoft.AspNetCore.Http.HttpRequest.Form" />,
        /// or <see cref="P:Microsoft.AspNetCore.Http.HttpRequest.Cookies" /> collections.
        /// </summary>
        /// <param name="request">Request to get values from</param>
        /// <param name="key">The name of the collection member to get. </param>
        /// <returns>The <see cref="P:Microsoft.AspNetCore.Http.HttpRequest.Query" />,
        /// <see cref="P:Microsoft.AspNetCore.Http.HttpRequest.Form" />,
        /// or <see cref="P:Microsoft.AspNetCore.Http.HttpRequest.Cookies" /> collection member specified in the
        /// <paramref name="key" /> parameter. If the specified <paramref name="key" /> is not found,
        /// then <see langword="null" /> is returned.</returns>
        public static string GetParameter(this HttpRequest request, string key)
        {
            string result = request.Query[key];
            if (result != null)
            {
                return result;
            }

            result = request.Form[key];
            if (result != null)
            {
                return result;
            }

            result = request.Cookies[key];
            if (result != null)
            {
                return result;
            }

            // There is no more ServerVariables property in the HttpRequest.
            //So this part of old HttpContextBase logic is skipped

            return null;
        }
    }
}