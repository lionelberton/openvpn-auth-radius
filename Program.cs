using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;
using auth.Logs;
using auth.Properties;
using FP.Radius;

namespace auth
{
    public class Program
    {
        /// <summary>
        /// The default log folder
        /// </summary>
        private static string _defaultLogFolder;
        /// <summary>
        /// The _error log file name
        /// </summary>
        public const string ErrorLogPrefixName = "errorlog";

        /// <summary>
        /// Application Log file name.
        /// </summary>
        public const string ApplicationLogPrefixName = "applicationlog";


        /// <summary>
        /// The Application log writter instance
        /// </summary>
        private static LogMessageBase _applicationLogWriterInstance;


        /// <summary>
        /// Entry point
        /// </summary>
        /// <param name="args"></param>
        /// <returns></returns>
        public static int Main(string[] args)
        {
            _defaultLogFolder = Settings.Default.LogFolder;
            string text = args[0];
            if (string.IsNullOrEmpty(_defaultLogFolder))
            {
                return 5;
            }

            InitLogger();


            if (!File.Exists(text))
            {
                Log.ErrorLog.WriteLine($"file is not existing at path {text}");
                return 1;
            }

            string[] array = File.ReadAllLines(text);
            if (array.Count() != 2)

            {
                Log.ErrorLog.WriteLine($"file {text} is not correct");
                return 1;
            }

            string userName = array[0];

            string password = array[1];

            if (Config.Settings == null)
            {
                Log.ErrorLog.WriteLine("Config is empty/unreadable");
                return 2;
            }

            if (Config.Settings.Servers == null || Config.Settings.Servers.Count == 0)
            {
                Log.ErrorLog.WriteLine("No servers found in config");
                return 3;
            }

            var res = Parallel.ForEach(Config.Settings.Servers.Cast<ServerElement>(), (server, state) =>
            {
                Log.InformationLog.WriteLine(string.Format("server name = {0} , retries = {1}, wait = {2}, autport = {3}",
                                                            server.Name, server.retries, server.wait, server.authport));

                var rc = new RadiusClient(server.Name, server.sharedsecret, server.wait * 1000, server.authport);

                Log.InformationLog.WriteLine("Radius client initializated");

                try
                {
                    var authPacket = rc.Authenticate(userName, password);
                    if (Config.Settings.NAS_IDENTIFIER != null)
                    {
                        authPacket.SetAttribute(new RadiusAttribute(RadiusAttributeType.NAS_IDENTIFIER, Encoding.ASCII.GetBytes(Config.Settings.NAS_IDENTIFIER)));
                    }

                    authPacket.SetAttribute(new RadiusAttribute(RadiusAttributeType.NAS_PORT_TYPE, BitConverter.GetBytes((int)NasPortType.ASYNC)));

                    var receivedPacket = rc.SendAndReceivePacket(authPacket, server.retries).Result;

                    if (receivedPacket == null)
                    {
                        Log.ErrorLog.WriteLine("Can't contact remote radius server !");
                    }

                    if (receivedPacket != null)
                    {
                        switch (receivedPacket.PacketType)
                        {
                            case RadiusCode.ACCESS_ACCEPT:
                                state.Stop();
                                break;
                            case RadiusCode.ACCESS_CHALLENGE:
                                Log.InformationLog.WriteLine("Access challenge");
                                break;
                            default:
                                Log.InformationLog.WriteLine(receivedPacket.PacketType.ToString());
                                break;
                        }


                    }

                }
                catch (Exception ex)
                {
                    Log.ErrorLog.WriteLine(ex);
                }

            });

            if (res.IsCompleted)
            {
                //On a parcouru tous les srveurs et on n'a rien trouvé
                Log.ErrorLog.WriteLine(string.Format("Authentication failed for: {0}", userName));
                return 4;
            }
            else
            {
                Log.SuccessLog.WriteLine(string.Format("Authentication success for user {0}", userName));
                return 0;
            }
        }

        /// <summary>
        /// Init the logger
        /// </summary>
        private static void InitLogger()
        {
            Directory.CreateDirectory(_defaultLogFolder);
            var version = Assembly.GetExecutingAssembly().GetName().Version;
            var pid = Process.GetCurrentProcess().Id;
            var maxN = GetMaxFileNumber(_defaultLogFolder, ErrorLogPrefixName, ApplicationLogPrefixName);
            maxN++;
            var applicationLogPath = Path.Combine(_defaultLogFolder, $"{ApplicationLogPrefixName}_{maxN:000}_{version}_{pid:00000}.txt");
            var errorLogPath = Path.Combine(_defaultLogFolder, $"{ErrorLogPrefixName}_{maxN:000}_{version}_{pid:00000}.txt");

            new ExceptionLogger(errorLogPath);
            _applicationLogWriterInstance = new LogMessageBase(applicationLogPath);

            Log.Instance.InformationLogBase = new ApplicationLogBase(true, StatusLevel.Information, _applicationLogWriterInstance);
            Log.Instance.SilentWarningLogBase = new ApplicationLogBase(true, StatusLevel.Warning, _applicationLogWriterInstance);
            Log.Instance.DisplayWarningLogBase = new ApplicationLogBase(true, StatusLevel.Warning, _applicationLogWriterInstance);
            Log.Instance.ErrorLogBase = new ApplicationLogBase(true, StatusLevel.Error, _applicationLogWriterInstance);
            Log.Instance.SuccessLogBase = new ApplicationLogBase(true, StatusLevel.Success, _applicationLogWriterInstance);
        }

        /// <summary>
        /// Gets the maximum file number.
        /// </summary>
        /// <param name="folderPath">The folder path.</param>
        /// <param name="errorLogPrefix">the error log prefix</param>
        /// <param name="applicationLogPrefix">the application log prefix</param>
        /// <returns></returns>
        private static int GetMaxFileNumber(string folderPath, string errorLogPrefix, string applicationLogPrefix)
        {
            int maxN = 0;
            // on gère les noms de fichiers suivants
            // nom_nnn_v.v.v.v_pid.txt
            // nom peut être soit errorlog ou applicationlog
            // nnn est un numéro incrémenter à chaque lancement de flowers.
            // v.v.v.v est le numero de version de flowers
            // pid est le process id de flowers.
            foreach (var filePath in Directory.EnumerateFiles(folderPath, "*.txt", SearchOption.TopDirectoryOnly))
            {
                var fileName = Path.GetFileName(filePath);
                var fileSplit = fileName.Split('_');
                if (fileSplit.Length == 4)
                {
                    if (fileSplit[0].Equals(errorLogPrefix, StringComparison.InvariantCulture)
                        || fileSplit[0].Equals(applicationLogPrefix, StringComparison.InvariantCulture))
                    {
                        if (int.TryParse(fileSplit[1], out var nnn))
                        {
                            maxN = Math.Max(maxN, nnn);
                        }
                    }
                }
            }
            return maxN;
        }
    }
}
