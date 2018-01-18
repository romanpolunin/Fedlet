namespace Sun.Identity.Common
{
    /// <summary>
    /// Some missed in System.Security.Cryptography.Xml constants
    /// </summary>
    public static class InternalSignedXml
    {
        /// <summary>Represents the Uniform Resource Identifier (URI) for the  <see cref="T:System.Security.Cryptography.RSA" /> SHA-256 signature method variation for XML digital signatures. This field is constant.</summary>
        public const string XmlDsigRSASHA256Url = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";

        /// <summary>Represents the Uniform Resource Identifier (URI) for the  <see cref="T:System.Security.Cryptography.RSA" /> SHA-384 signature method variation for XML digital signatures. This field is constant.</summary>
        public const string XmlDsigRSASHA384Url = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384";

        /// <summary>Represents the Uniform Resource Identifier (URI) for the  <see cref="T:System.Security.Cryptography.RSA" /> SHA-512 signature method variation for XML digital signatures. This field is constant.</summary>
        public const string XmlDsigRSASHA512Url = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512";
    }
}