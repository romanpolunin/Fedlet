/*
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS HEADER.
 * 
 * Copyright (c) 2010 Sun Microsystems Inc. All Rights Reserved
 * 
 * The contents of this file are subject to the terms
 * of the Common Development and Distribution License
 * (the License). You may not use this file except in
 * compliance with the License.
 * 
 * You can obtain a copy of the License at
 * https://opensso.dev.java.net/public/CDDLv1.0.html or
 * opensso/legal/CDDLv1.0.txt
 * See the License for the specific language governing
 * permission and limitations under the License.
 * 
 * When distributing Covered Code, include this CDDL
 * Header Notice in each file and include the License file
 * at opensso/legal/CDDLv1.0.txt.
 * If applicable, add the following below the CDDL Header,
 * with the fields enclosed by brackets [] replaced by
 * your own identifying information:
 * "Portions Copyrighted [year] [name of copyright owner]"
 * 
 * $Id: FedletCertificateFactory.cs,v 1.1 2010/01/12 18:04:55 ggennaro Exp $
 */

using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Sun.Identity.Properties;

namespace Sun.Identity.Common
{
	/// <summary>
	/// Class for performing X509 certificate related tasks.
	/// </summary>
    public class FedletCertificateFactory : IFedletCertificateFactory
	{
	    /// <summary>
		/// Finds the X509 certificate in this machine's key store.
		/// </summary>
		/// <param name="friendlyName">
		/// Friendly name of the certificate
		/// </param>
		/// <returns>
		/// X509Certificate2 object that matches the given friendly name.
		/// </returns>
		public X509Certificate2 GetCertificateByFriendlyName(string friendlyName)
		{
	        var store = new X509Store(StoreLocation.LocalMachine);
			string errorMessage = null;

			try
			{
				store.Open(OpenFlags.ReadOnly);

				var certEnum = store.Certificates.GetEnumerator();
				while (certEnum.MoveNext())
				{
					if (certEnum.Current?.FriendlyName == friendlyName)
					{
					    var cert = certEnum.Current;
					    return cert;
					}
				}
			}
			catch (CryptographicException ce)
			{
				errorMessage = ce.Message;
			}
			catch (SecurityException se)
			{
				errorMessage = se.Message;
			}
			finally
			{
			    store.Close();
			}

	        if (errorMessage != null)
			{
                LoggerFactory.GetLogger(typeof(FedletCertificateFactory)).Warning("{0} {1}", Resources.FedletCertificateFactoryGetByFriendlyNameFailed, errorMessage);
			}

	        return null;
		}
	}
}