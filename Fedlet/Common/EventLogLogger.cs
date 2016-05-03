/*
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS HEADER.
 * 
 * Copyright (c) 2009 Sun Microsystems Inc. All Rights Reserved
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
 * $Id: FedletLogger.cs,v 1.1 2009/06/11 18:37:59 ggennaro Exp $
 * $Id: EventLogLogger.cs,v 1.1 2011/05/24 18:37:59 dburlingame Exp $
 */

using System;
using System.Configuration;
using System.Diagnostics;

namespace Sun.Identity.Common
{
    /// <summary>
	/// Simple class for logging events to the Windows Application Log. The
	/// &lt;appSettings/&gt; section of the Web.config would be the place to
	/// specify the logging level (either ERROR, WARNING, or INFO).  An
	/// example Web.config file would have the following:
	/// <para>
	///     &lt;appSettings&gt;
	///         &lt;add key="fedletLogLevel" value="info" /&gt;
	///     &lt;/appSettings&gt;
	/// </para>
	/// </summary>
    public class EventLogLogger : ILogger
    {

        /// <summary>
        /// Parameter key in the &lt;appSettings/&gt; section of the 
        /// Web.config file of the desired .NET application for specifying 
        /// the log level. 
        /// </summary>
        public const string AppSettingParameter = "fedletLogLevel";

        /// <summary>
        /// Constant for the ERROR log level.
        /// </summary>
        public const string LogLevelError = "ERROR";

        /// <summary>
        /// Constant for the INFO log level.
        /// </summary>
        public const string LogLevelInfo = "INFO";

        /// <summary>
        /// Constant for the WARNING log level.
        /// </summary>
        public const string LogLevelWarning = "WARNING";

        /// <summary>
        /// Constant that specifies the Windows event log to use, in this
        /// case, the Application log.
        /// </summary>
        public const string Log = "Application";

        /// <summary>
        /// Constant that specifies the source of the log entry, in this
        /// case, the Fedlet.
        /// </summary>
        public const string LogSource = "Fedlet";

        private static string _logLevel;

        private static string GetLogLevel()
        {
            if (_logLevel == null)
            {
                _logLevel = ConfigurationManager.AppSettings[AppSettingParameter];
                _logLevel = _logLevel?.ToUpperInvariant();
            }
            return _logLevel;
        }

        ///<summary>Returns true if Warn level logging is enabled</summary>
        public bool IsErrorEnabled => IsEnabled(EventLogEntryType.Error);

        ///<summary>Returns true if Info level logging is enabled</summary>
        public bool IsInfoEnabled => IsEnabled(EventLogEntryType.Information);

        ///<summary>Returns true if Warn level logging is enabled</summary>
        public bool IsWarnEnabled => IsEnabled(EventLogEntryType.Warning);

        /// <summary>
        /// Method to write an error message to the event log.
        /// </summary>
        /// <param name="ex">The exception to be written.</param>
        /// <param name="message">Message to be written.</param>
        public void Error(Exception ex, string message)
		{
			LogMessage(message + Environment.NewLine + ex, EventLogEntryType.Information);
    	}

        /// <summary>
        /// Method to write an error message to the event log.
        /// </summary>
        public void Error(Exception ex, string format, params object[] args)
		{
			LogMessage(string.Format(format, args) + Environment.NewLine + ex, EventLogEntryType.Information);
    	}

    	/// <summary>
        /// Method to write an information message to the event log.
        /// </summary>
        /// <param name="message">Message to be written.</param>
        public void Info(string message)
        {
            LogMessage(message, EventLogEntryType.Information);
        }

        /// <summary>
        /// Method to write an information message to the event log.
        /// </summary>
        public void Info(string format, params object[] args)
        {
            Info(string.Format(format, args));
        }

        /// <summary>
        /// Method to write a warning message to the event log.
        /// </summary>
        /// <param name="message">Message to be written.</param>
        public void Warning(string message)
        {
            LogMessage(message, EventLogEntryType.Warning);
        }

        /// <summary>
        /// Method to write a warning message to the event log.
        /// </summary>
        public void Warning(string format, params object[] args)
        {
            Warning(string.Format(format, args));
        }

        /// <summary>
        /// Method to write a message with the given entry type.  Currently
        /// only Info, Warning, and Error are supported from the default
        /// messages available from the framework.
        /// </summary>
        /// <see cref="System.Diagnostics.EventLogEntryType"/>
        /// <param name="message">Message to be written.</param>
        /// <param name="entryType">
        /// EventLogEntryType to associate with message.
        /// </param>
        private void LogMessage(string message, EventLogEntryType entryType)
        {
            if(IsEnabled(entryType))
            {
                EventLog.WriteEntry(LogSource, message, entryType);
            }
        }

        private bool IsEnabled(EventLogEntryType entryType)
        {
            string logLevel = GetLogLevel();
            if (string.IsNullOrEmpty(logLevel))
            {
                return false;
            }

            return (entryType == EventLogEntryType.Error && logLevel == LogLevelError)
                   || (entryType <= EventLogEntryType.Warning && logLevel == LogLevelWarning)
                   || (entryType <= EventLogEntryType.Information && logLevel == LogLevelInfo);
        }
    }
}