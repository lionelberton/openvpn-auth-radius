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
        /// The contents
        /// </summary>
        private enum FileContent
        {
            /// <summary>
            /// The user name
            /// </summary>
            userName = 0,
            /// <summary>
            /// The password
            /// </summary>
            /// <remarks>if the double factor is used, the second line contains password and double facor encoded in base 64. If not the password in clear</remarks>
            password = 1,
        }

        /// <summary>
        /// The authetication data
        /// </summary>
        private enum AuthenticationData
        {
            /// <summary>
            /// SCRV1
            /// </summary>
            SCRV1 = 0,
            /// <summary>
            /// The password encoded in base 64
            /// </summary>
            PasswordBased64,
            /// <summary>
            /// The response encoded in base 64
            /// </summary>
            ResponseBased64
        }


        /// <summary>
        /// Entry point
        /// </summary>
        /// <param name="args">Contains the path of the file with connection info (using via file)</param>
        /// <returns></returns>
        public static int Main(string[] args)
        {
            _defaultLogFolder = Settings.Default.LogFolder;
            var path = args[0];
            if (string.IsNullOrEmpty(_defaultLogFolder))
            {
                Log.ErrorLog.WriteLine("No folder defined for the logs.");
                return 5;
            }

            InitLogger();

            if (!File.Exists(path))
            {
                Log.ErrorLog.WriteLine($"file is not existing at path {path}");
                return 1;
            }

            //The file must contains two lines
            var array = File.ReadAllLines(path);
            if (array.Length != 2)
            {
                Log.ErrorLog.WriteLine($"file {path} is not correct");
                return 6;
            }

            //user name is on first row
            var userName = array[(int)FileContent.userName];
            string password;
            string doubleFactor = null;
            //If the second row strat with SCRV1, the MFA is activated
            if (array[(int)FileContent.password].Substring(0, 5) == "SCRV1")
            {
                //we need to split on ':' to retrieve password and MFA code
                //structure SCRV1:base64_pass:base64_response
                var secondLineData = array[(int)FileContent.password].Split(':');
                if (secondLineData.Length == 3)
                {
                    password = Encoding.UTF8.GetString(Convert.FromBase64String(secondLineData[(int)AuthenticationData.PasswordBased64]));
                    doubleFactor = Encoding.UTF8.GetString(Convert.FromBase64String(secondLineData[(int)AuthenticationData.ResponseBased64]));
                }
                else
                {
                    Log.ErrorLog.WriteLine("Error in authentication. The password row doesn't contains the requested elements.");
                    return 7;
                }
            }
            else
            {
                password = array[(int)FileContent.password];
            }


            if (Config.Settings == null)
            {
                Log.ErrorLog.WriteLine("The plugin configuration is empty/unreadable");
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

                Log.InformationLog.WriteLine("Radius client is initializated.");

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
                        Log.ErrorLog.WriteLine("Can't contact remote radius server {0}!", server.Name);
                    }


                    Log.InformationLog.WriteLine("List of the attributes received");
                    foreach (var attribute in receivedPacket.Attributes)
                    {
                        Log.InformationLog.WriteLine(attribute.Type.ToString() + " " + attribute.Value);
                    }

                    if (receivedPacket != null)
                    {
                        //Depending of the packet response type, we have to manage different cases
                        switch (receivedPacket.PacketType)
                        {
                            //MFA not activated. The access is granted
                            case RadiusCode.ACCESS_ACCEPT:
                                if (!string.IsNullOrEmpty(doubleFactor))
                                {
                                    Log.SilentWarningLog.WriteLine("Double factor must be activated for the user {0}", userName);
                                }
                                state.Stop();
                                break;
                            //A radius challenge is requested
                            case RadiusCode.ACCESS_CHALLENGE:
                                Log.InformationLog.WriteLine("Starting the access challenge for user {0}", userName);
                                var packet = new RadiusPacket(RadiusCode.ACCESS_REQUEST);
                                packet.SetAttribute(receivedPacket.Attributes.First(x => x.Type == RadiusAttributeType.STATE));
                                packet.SetAuthenticator(server.sharedsecret);
                                byte[] data = Utils.EncodePapPassword(Encoding.ASCII.GetBytes(doubleFactor), packet.Authenticator, server.sharedsecret);
                                packet.SetAttribute(new RadiusAttribute(RadiusAttributeType.USER_PASSWORD, data));
                                var returnPacketForChallenge = rc.SendAndReceivePacket(packet).Result;

                                if (returnPacketForChallenge == null)
                                {
                                    Log.ErrorLog.WriteLine("Return packet for RADIUS challenge is null for user {0}.", userName);
                                }
                                else
                                {
                                    Log.InformationLog.WriteLine("Packet type: " + returnPacketForChallenge.PacketType);
                                    //If the Radius challenge is completed, the packet type must be access_accept
                                    if (returnPacketForChallenge.PacketType == RadiusCode.ACCESS_ACCEPT)
                                    {
                                        state.Stop();
                                    }
                                }
                                break;
                            //Other cases
                            default:
                                Log.InformationLog.WriteLine("Packet type received is {0}", receivedPacket.PacketType.ToString());
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
