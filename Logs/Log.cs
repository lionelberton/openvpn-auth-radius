using System.IO;

namespace auth.Logs
{
    /// <summary>
    /// Log that can be used in applications.
    /// </summary>
    /// <seealso cref="Princeps.Framework.IO.LogBase" />
    public class Log : LogBase
    {
        private static Log _instance;
        /// <summary>
        /// Gets the instance.
        /// </summary>
        /// <value>
        /// The instance.
        /// </value>
        public static Log Instance => _instance ?? (_instance = new Log());

        /// <summary>
        /// Prevents a default instance of the <see cref="Log"/> class from being created.
        /// </summary>
        private Log()
        { }

        /// <summary>
        /// Gets the success log.
        /// </summary>
        /// <value>
        /// The success log.
        /// </value>
        public static TextWriter SuccessLog => Instance.SuccessLogBase;
        /// <summary>
        /// Gets the information log.
        /// </summary>
        /// <value>
        /// The information log.
        /// </value>
        public static TextWriter InformationLog => Instance.InformationLogBase;
        /// <summary>
        /// Gets the silent warning log.
        /// </summary>
        /// <value>
        /// The silent warning log.
        /// </value>
        public static TextWriter SilentWarningLog => Instance.SilentWarningLogBase;
        /// <summary>
        /// Gets the display warning log.
        /// </summary>
        /// <value>
        /// The display warning log.
        /// </value>
        public static TextWriter DisplayWarningLog => Instance.DisplayWarningLogBase;
        /// <summary>
        /// Gets the error log.
        /// </summary>
        /// <value>
        /// The error log.
        /// </value>
        public static TextWriter ErrorLog => Instance.ErrorLogBase;
    }
}
