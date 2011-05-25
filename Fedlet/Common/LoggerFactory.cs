using System;

namespace Sun.Identity.Common
{
    public static class LoggerFactory
    {
        private static Func<Type, ILogger> GetLoggerCallback = type => new EventLogLogger();

        ///<summary>
        /// Replaces the current callback used to determine an ILogger for a given Type
        ///</summary>
        public static void SetFactory(Func<Type, ILogger> factoryCallback)
        {
            GetLoggerCallback = factoryCallback;
        }

        ///<summary>
        ///</summary>
        ///<typeparam name="T"></typeparam>
        ///<returns></returns>
        public static ILogger GetLogger<T>()
        {
            return GetLogger(typeof(T));
        }

        ///<summary>
        ///</summary>
        ///<param name="type"></param>
        ///<returns></returns>
        public static ILogger GetLogger(Type type)
        {
            return GetLoggerCallback(type);
        }
    }
}