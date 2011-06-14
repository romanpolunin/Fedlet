using System;

namespace Sun.Identity.Common
{
    ///<summary>Defines the logging interface used by Fedlet</summary>
    public interface ILogger
	{
		///<summary>Returns true if Warn level logging is enabled</summary>
		bool IsErrorEnabled { get; }

        ///<summary>Returns true if Info level logging is enabled</summary>
        bool IsInfoEnabled { get; }

        ///<summary>Returns true if Warn level logging is enabled</summary>
		bool IsWarnEnabled { get; }

		/// <summary>
		/// Method to write an error message to the event log.
		/// </summary>
		/// <param name="ex">The exception to be written.</param>
		/// <param name="message">Message to be written.</param>
		void Error(Exception ex, string message);

		/// <summary>
		/// Method to write an error message to the event log.
		/// </summary>
		void Error(Exception ex, string format, params object[] args);

        /// <summary>
        /// Method to write an information message to the event log.
        /// </summary>
        /// <param name="message">Message to be written.</param>
        void Info(string message);

        /// <summary>
        /// Method to write an information message to the event log.
        /// </summary>
        void Info(string format, params object[] args);

        /// <summary>
        /// Method to write a warning message to the event log.
        /// </summary>
        /// <param name="message">Message to be written.</param>
        void Warning(string message);

        /// <summary>
        /// Method to write a warning message to the event log.
        /// </summary>
		void Warning(string format, params object[] args);
    }
}