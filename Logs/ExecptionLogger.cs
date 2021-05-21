using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace auth.Logs
{
    /// <summary>
    /// Log exceptions for the entire application.
    /// </summary>
    public class ExceptionLogger
    {
        /// <summary>
        /// The log writer
        /// </summary>
        private readonly FileLogWriter _LogWriter;

        /// <summary>
        /// The date format for the log.
        /// </summary>
        public static readonly string DateFormat = @"dd/MM/yyyy HH:mm:ss";

        /// <summary>
        /// Gets or sets a value indicating whether to use time stamp.
        /// </summary>
        /// <value>
        ///   <c>true</c> if use time stamp; otherwise, <c>false</c>.
        /// </value>
        public bool UseTimeStamp { get; set; }
        /// <summary>
        /// Instance of the exception logger for the application
        /// </summary>
        public static ExceptionLogger Instance { get; private set; }

        /// <summary>
        /// Initializes a new instance of the <see cref="ExceptionLogger"/> class.
        /// </summary>
        /// <param name="errorLogPath">The error log path.</param>
        public ExceptionLogger(string errorLogPath)
            : this(new FileLogWriter(errorLogPath))
        { }

        /// <summary>
        /// Initializes a new instance of the <see cref="ExceptionLogger"/> class.
        /// </summary>
        private ExceptionLogger(FileLogWriter logWriter)
        {
            UseTimeStamp = true;
            _LogWriter = logWriter;
            AppDomain.CurrentDomain.UnhandledException += new UnhandledExceptionEventHandler(CurrentDomain_UnhandledException);
            AppDomain.CurrentDomain.FirstChanceException += new EventHandler<System.Runtime.ExceptionServices.FirstChanceExceptionEventArgs>(CurrentDomain_FirstChanceException);
            AppDomain.CurrentDomain.AssemblyResolve += new ResolveEventHandler(CurrentDomain_AssemblyResolve);
            AppDomain.CurrentDomain.TypeResolve += new ResolveEventHandler(CurrentDomain_TypeResolve);
            Instance = this;
        }

        /// <summary>
        /// Called when the CLR cannot find a Type.
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="args"></param>
        /// <returns></returns>
        private Assembly CurrentDomain_TypeResolve(object sender, ResolveEventArgs args)
        {
            LogMessage("TYPE RESOLVE EXCEPTION-------- " + args.Name + " § " + args.RequestingAssembly.FullName);
            return null;
        }
        /// <summary>
        /// Called when the CLR does not find an assembly. We are using this for loading multiple versions of plugins.
        /// We search for assemblyname.dll first into the project "libs" folder, 
        /// then into the global "plugins\assemblyname_assemblyversion\" folder, then into the project "plugins\assemblyname_assemblyversion\" folder.
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="args"></param>
        /// <returns></returns>
        protected virtual Assembly CurrentDomain_AssemblyResolve(object sender, ResolveEventArgs args)
        {
            var asm = new AssemblyName(args.Name);
            if (asm.Name.EndsWith("resources")) return null;

            string msg = "ASSEMBLY RESOLVE EXCEPTION---------- Need " + args.Name + " for ";
            if (args.RequestingAssembly != null)
            {
                msg += args.RequestingAssembly.FullName;
            }
            LogMessage(msg);

            foreach (var loadedAss in AppDomain.CurrentDomain.GetAssemblies())
            {
                if (loadedAss.FullName == args.Name)
                {
                    return loadedAss;
                }
            }
            return null;
        }
        /// <summary>
        /// Log first chance exception when they occur. It does not mean that they won't be trapped.
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void CurrentDomain_FirstChanceException(object sender, System.Runtime.ExceptionServices.FirstChanceExceptionEventArgs e)
        {
            if (_suspendedFirstChanceLogging.Value != 0) { return; }

            if (e.Exception is OperationCanceledException)
            {
                //Cette exception est levée à la fin de la simulation par le STA task scheduler pour débloquer la blockingcollection. 
                //On a pas besoin de la stacktrace pour ça, même si elle peut être levée à d'autres endroits.
                //surtout qu'elle est levée une fois par thread du scheduleur donc 8 fois pour un CPU 4 coeurs.
            }
            else
            {
                if (e.Exception is OutOfMemoryException)
                {
                    //on veut tracer la quantité de mémoire au moment de l'exception.
                    var process = System.Diagnostics.Process.GetCurrentProcess();
                    LogMessage(string.Format("Memory Working Set = {0:N0} Bytes.", process.WorkingSet64));
                }
                LogMessage("FIRST CHANCE EXCEPTION--------------- " + ExceptionToString(e.Exception, true));
            }
        }

        /// <summary>
        /// Handles unhandled exceptions on the domain.
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void CurrentDomain_UnhandledException(object sender, UnhandledExceptionEventArgs e)
        {
            //on loggue l'erreur dans le fichier en premier pour voir les erreurs WPF.
            LogMessage("DOMAIN UNHANDLED EXCEPTION--------------- " + e.ExceptionObject.ToString());
            // la msgbox qu'on avait n'était pas utile et pouvait provoquer des deadlocks
        }

        /// <summary>
        /// Logs the timestamp.
        /// </summary>
        /// <param name="message">The message.</param>
        protected void LogMessage(string message)
        {
            var timeStampedMessage = (UseTimeStamp ? DateTime.Now.ToString(DateFormat) + " " : string.Empty) + message;
            _LogWriter.Write(timeStampedMessage);
        }

        /// <summary>
        /// Convert Exceptions to string.
        /// </summary>
        /// <param name="exception">The exception.</param>
        /// <param name="withFullStackTrace">if set to <c>true</c> will log the exception with full stack trace, otherwise the stack is truncated on the first try/catch block.</param>
        /// <returns></returns>
        protected string ExceptionToString(Exception exception, bool withFullStackTrace)
        {
            StringBuilder text = new StringBuilder(exception.ToString());
            //en général une first chance exception n'a qu'une seule ligne dans sa stacktrace (par défaut dans .net), ce qui n'est pas suffisant.
            if (withFullStackTrace)
            {
                text.AppendLine();
                text.AppendLine("--- Full Stack Trace ---");
                text.AppendLine((new System.Diagnostics.StackTrace(2, true)).ToString()); //on skippe 2 frames: cette fonction et son parent.
            }
            if (exception is ReflectionTypeLoadException reflectionException)
            {
                foreach (var loaderException in reflectionException.LoaderExceptions)
                {
                    if (loaderException != null)
                    {
                        text.AppendLine(ExceptionToString(loaderException, false));
                    }
                }
            }
            return text.ToString();
        }

        /// <summary>
        /// The suspended first chance logging counter
        /// </summary>
        private readonly ThreadLocal<int> _suspendedFirstChanceLogging = new ThreadLocal<int>(() => 0);

        /// <summary>
        /// Suspends the first chance logging.
        /// </summary>
        public void SuspendFirstChanceLoggingOfCurrentThread()
        {
            //la variable est par thread donc pas de problème de threading!
            _suspendedFirstChanceLogging.Value += 1;
        }

        /// <summary>
        /// Resumes the first chance logging.
        /// </summary>
        /// <exception cref="System.Exception">Invalid nesting of Suspend/Resume first chance exception logging.</exception>
        public void ResumeFirstChanceLoggingOfCurrentThread()
        {
            _suspendedFirstChanceLogging.Value -= 1;
            if (_suspendedFirstChanceLogging.Value < 0)
            {
                throw new Exception("Invalid nesting of Suspend/Resume first chance exception logging.");
            }
        }
    }
}
