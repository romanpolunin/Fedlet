using System.Security.Cryptography.X509Certificates;

namespace Sun.Identity.Common
{
    /// <summary>
    /// Certificate reader.
    /// </summary>
    public interface IFedletCertificateFactory
    {
        /// <summary>
        /// Retrieves a certificate by friendly name.
        /// </summary>
        X509Certificate2 GetCertificateByFriendlyName(string friendlyName, ILogger logger);
    }
}