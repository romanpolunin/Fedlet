using System.Security.Cryptography.X509Certificates;

namespace Sun.Identity.Common
{
    public interface IFedletCertificateFactory
    {
        X509Certificate2 GetCertificateByFriendlyName(string friendlyName);
    }
}