using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace auth.Logs
{
    /// <summary>
    /// Base class to create log providers.
    /// </summary>
    public class LogBase
    {
        private TextWriter _successLog = Console.Out;
        /// <summary>
        /// Provide an access to a log channel. Implementation is left to the clients.
        /// </summary>
        public TextWriter SuccessLogBase { get => _successLog; set { _successLog = value ?? Console.Out; } }

        private TextWriter _logInformation = Console.Out;
        /// <summary>
        /// Provide an access to a log channel. Implementation is left to the clients.
        /// </summary>
        public TextWriter InformationLogBase { get => _logInformation; set { _logInformation = value ?? Console.Out; } }

        private TextWriter _silentWarningLog = Console.Out;
        /// <summary>
        /// Provide an access to a log channel. Implementation is left to the clients.
        /// </summary>
        public TextWriter SilentWarningLogBase { get => _silentWarningLog; set { _silentWarningLog = value ?? Console.Out; } }

        private TextWriter _displayWarningLog = Console.Out;
        /// <summary>
        /// Provide an access to a log channel. Implementation is left to the clients.
        /// </summary>
        public TextWriter DisplayWarningLogBase { get => _displayWarningLog; set { _displayWarningLog = value ?? Console.Out; } }

        private TextWriter _logError = Console.Out;
        /// <summary>
        /// Provide an access to a log channel. Implementation is left to the clients.
        /// </summary>
        public TextWriter ErrorLogBase { get => _logError; set { _logError = value ?? Console.Out; } }

        /// <summary>
        /// Initializes a new instance of the <see cref="LogBase"/> class.
        /// </summary>
        protected LogBase()
        { }
    }
}
