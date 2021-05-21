using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace auth.Logs
{
    /// <summary>
    /// Write log to a file.
    /// </summary>
    /// <seealso cref="Princeps.Framework.ErrorLogBase" />
    internal class FileLogWriter
    {
        /// <summary>
        /// The lock for thread safe access to Log function.
        /// </summary>
        private readonly object _logLock = new object();
        /// <summary>
        /// flag to indicate that the thread is already handling an exception. 
        /// It is used to avoid recursive calls to the log file 
        /// due to an exception raised on the error log file access.
        /// </summary>
        private bool _locked = false;
        /// <summary>
        /// The error log path
        /// </summary>
        private readonly string _errorLogPath;

        /// <summary>
        /// Initializes a new instance of the <see cref="FileLogWriter"/> class.
        /// </summary>
        /// <param name="errorLogPath">The error log path.</param>
        internal FileLogWriter(string errorLogPath)
        {
            _errorLogPath = errorLogPath;
        }

        /// <summary>
        /// Writes the specified message.
        /// </summary>
        /// <param name="message">The message.</param>
        public void Write(string message)
        {
            //en multithread l'accès simultané au fichier plante.
            //on évite aussi un appel récursif si l'ouverture du fichier lève une exception.
            lock (_logLock)
            {
                if (!_locked)
                {
                    _locked = true;
                    try
                    {
                        using (var sw = new StreamWriter(_errorLogPath, true))
                        {
                            sw.WriteLine(message);
                        }
                    }
                    catch { }
                    finally
                    {
                        _locked = false;
                    }
                }
            }
        }
    }
}
