using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.IO;
using System.Linq;
using CloudStreamForms.Cryptography;
using System.Net.NetworkInformation;

namespace CloudStreamAccountServerWindows
{
    class Program
    {
        public static string GetLocalIPv4(NetworkInterfaceType _type)
        {
            try {
                string output = "";
                foreach (NetworkInterface item in NetworkInterface.GetAllNetworkInterfaces()) {
                    if (item.NetworkInterfaceType == _type && item.OperationalStatus == OperationalStatus.Up) {
                        foreach (UnicastIPAddressInformation ip in item.GetIPProperties().UnicastAddresses) {
                            if (ip.Address.AddressFamily == AddressFamily.InterNetwork) {
                                output = ip.Address.ToString();
                            }
                        }
                    }
                }
                return output;
            }
            catch (Exception) {
                return "";
            }
        }

        public static string GetLocalIPAddress()
        {
            return GetLocalIPv4(NetworkInterfaceType.Wireless80211);
        }


        public struct AccountData
        {
            public string name; // HASHED NAME
            public string password; // HASHED PASSWORD
            public string data; // ENCRYPTED DATA
        }

        static Dictionary<string, AccountData> accounts = new Dictionary<string, AccountData>(); // ACCOUNTS WILL BE INDEXED BY HASHED NAME

        static string fileLocation = AppDomain.CurrentDomain.BaseDirectory;
        public const string dataLocation = "data.txt";
        public const string configLocation = "config.txt";

        static string publicUrl = "";
        static string currentUrl;
        const int port = 51338;

        public static string RemoveHtmlChars(string inp)
        {
            return System.Net.WebUtility.HtmlDecode(inp);
        }
        public static string FindHTML(string all, string first, string end, int offset = 0, bool readToEndOfFile = false, bool decodeToNonHtml = false)
        {
            int firstIndex = all.IndexOf(first);
            if (firstIndex == -1) {
                return "";
            }
            int x = firstIndex + first.Length + offset;

            all = all.Substring(x, all.Length - x);
            int y = all.IndexOf(end);
            if (y == -1) {
                if (readToEndOfFile) {
                    y = all.Length;
                }
                else {
                    return "";
                }
            }
            //  print(x + "|" + y);

            string s = all.Substring(0, y);
            if (decodeToNonHtml) {
                return RemoveHtmlChars(s);
            }
            else {
                return s;
            }
        }

        public const string configHeader = "CONFIG";
        public const string dataHeader = "USERDATA";

        public static void SaveConfig()
        {
            string text = $"{configHeader}\n";
            text += $"PUBLICURL<{publicUrl}>\n";
            File.WriteAllText(fileLocation + configLocation, text);
        }

        public static void SaveUserdata()
        {
            string text = $"{dataHeader}\n";

            foreach (var key in accounts.Keys) {
                AccountData account = accounts[key];
                text += $"NAME<{account.name}>PASSWORD<{account.password}>DATA<{account.data}>\n";
            }

            File.WriteAllText(fileLocation + dataLocation, text);
        }

        public static void SetUp()
        {
            bool configExists = File.Exists(fileLocation + configLocation);
            if (configExists) {
                Console.WriteLine("Use current config Y/N [Y]");
                var key = Console.ReadKey().Key;
                if (key == ConsoleKey.N) {
                    configExists = false;
                }
                Console.WriteLine("");
            }
            if (configExists) {
                string config = File.ReadAllText(fileLocation + configLocation);
                if (!config.StartsWith(configHeader)) { // CORUPTED
                    File.Delete(fileLocation + configLocation);
                }
                else {
                    string[] configLines = config.Split('\n');
                    for (int i = 0; i < configLines.Length; i++) {
                        string line = configLines[i];
                        if (line.StartsWith("PUBLICURL<")) {
                            publicUrl = FindHTML(line, "<", ">");
                        }
                    }
                }
            }

            if (publicUrl == "") {
                Console.WriteLine("Please enter an url, (Leave empty for local network)");
                publicUrl = Console.ReadLine();
            }

            if (publicUrl == "localhost" || publicUrl == "") {
                publicUrl = "localhost";
                currentUrl = $"http://{GetLocalIPAddress()}:{port}/account/";
            }
            else {
                currentUrl = publicUrl;
            }
            SaveConfig();

            if (File.Exists(fileLocation + dataLocation)) {
                string data = File.ReadAllText(fileLocation + dataLocation);

                if (!data.StartsWith(dataHeader)) { // Currupted data
                    Console.WriteLine("Userdata is currupted, delete file y/n? ");
                    ConsoleKeyInfo key = Console.ReadKey();
                    if (key.Key == ConsoleKey.Y) {
                        File.Delete(fileLocation + dataLocation);
                    }
                    else {
                        Console.WriteLine("Could not read data, exiting the program");
                        Environment.Exit(-1);
                    }
                }
                else {
                    string[] lines = data.Split('\n');

                    string ReadLine(string d, string find)
                    {
                        return FindHTML(d, find + "<", ">");
                    }

                    foreach (var line in lines) {
                        if (line.StartsWith("#")) continue;
                        if (line.StartsWith("NAME<")) {
                            string name = ReadLine(line, "NAME");
                            string password = ReadLine(line, "PASSWORD");
                            string userdata = ReadLine(line, "DATA");
                            accounts[name] = new AccountData() {
                                name = name,
                                data = userdata,
                                password = password,
                            };
                        }
                    }
                }
            }
        }

        public static bool EditAccountData(string name, string password, string data)
        {
            try {
                if (accounts.ContainsKey(name)) {
                    var acc = accounts[name];
                    if (CheckIsCorrectPassword(password, acc.password)) {
                        acc.data = data;
                        accounts[name] = acc;
                        SaveUserdata();
                        Console.WriteLine("Edit account: " + name);
                        return true;
                    }
                }
                return false;
            }
            catch (Exception) {
                return false;
            }
        }

        public static bool LoginToAccount(string name, string password, out string data)
        {
            try {
                data = "";
                if (accounts.ContainsKey(name)) {
                    var acc = accounts[name];
                    if (CheckIsCorrectPassword(password, acc.password)) {
                        data = acc.data;
                        Console.WriteLine("Login account: " + name);
                        return true;
                    }
                }
                return false;
            }
            catch (Exception) {
                data = "";
                return false;
            }
        }

        static Dictionary<string, bool> usedKeys = new Dictionary<string, bool>();
        public static bool CheckIsCorrectPassword(string password, string correctPassword)
        {
            try {
                string decrypt = StringCipher.Decrypt(password, correctPassword);
                if (decrypt.Contains("CORRECTPASS")) {
                    DateTime time = DateTime.FromBinary(long.Parse(FindHTML(decrypt, "CORRECTPASS[", "]")));
                    if (DateTime.UtcNow.Subtract(time).TotalSeconds < 20) { // 20 sec window
                        string key = correctPassword + time.ToBinary();
                        if (usedKeys.ContainsKey(key)) {
                            Console.WriteLine("Duplicate key from " + correctPassword);
                            return false;
                        }
                        usedKeys[key] = true;
                        return true;
                    }
                    else {
                        Console.WriteLine("Out of date key from " + correctPassword);
                        return false;
                    }
                }
                Console.WriteLine("Incorrect pass from " + correctPassword);
                return false;
            }
            catch (Exception) {
                return false;
            }
        }

        public static bool RegisterAccount(string name, string password, string data)
        {
            try {
                if (accounts.ContainsKey(name)) {
                    return false;
                }

                Console.WriteLine("Created account: " + name);
                accounts[name] = new AccountData() {
                    name = name,
                    password = password,
                    data = data,
                };
                SaveUserdata();

                return true;
            }
            catch (Exception _ex) {
                return false;
            }
        }

        public enum Logintype
        {
            CreateAccount = 0,
            LoginAccount = 1,
            EditAccount = 2,
        }
        public enum LoginErrorType
        {
            Ok = 0,
            InternetError = 1,
            WrongPassword = 2,
            UsernameTaken = 3,
        }


        static void Main(string[] args)
        {
            SetUp();
            try {
                using (var listener = new HttpListener()) { 
                    listener.Prefixes.Add(currentUrl);
                    listener.Start();
                    Console.Clear();
                    Console.WriteLine("Starting at " + currentUrl);
                    while (true) {
                        HttpListenerContext context = listener.GetContext();
                        HttpListenerRequest request = context.Request;
                        Console.WriteLine("Request from " + request.UserAgent);
                        /*foreach (var key in request.Headers.AllKeys) { // EXTRA DEBUG INFO
                            Console.WriteLine(key + ":" + request.Headers[key]);
                        }*/
                        if (request.Headers.AllKeys.Contains("LOGINTYPE")) {
                            using (HttpListenerResponse response = context.Response) {
                                try {
                                    Logintype logintype = (Logintype)int.Parse(request.Headers["LOGINTYPE"]);
                                    string name = request.Headers["NAME"];
                                    string data = "";
                                     
                                    if (logintype != Logintype.LoginAccount) {
                                        using (var reader = new StreamReader(request.InputStream,
                                    request.ContentEncoding)) {
                                            data = reader.ReadToEnd();
                                        }
                                        //data = request.Headers["DATA"];
                                    }
                                    string hashPass = request.Headers[logintype == Logintype.CreateAccount ? "HASHPASSWORD" : "ONETIMEPASSWORD"];

                                    const string correctHeader = "OKDATA";

                                    string responseData = "";
                                    if (logintype == Logintype.CreateAccount) {
                                        responseData = RegisterAccount(name, hashPass, data) ? $"{correctHeader}\n" : $"ERRORCODE[{(int)LoginErrorType.UsernameTaken}]";
                                    }
                                    else if (logintype == Logintype.LoginAccount) {
                                        bool succ = LoginToAccount(name, hashPass, out string _data);
                                        if (succ) {
                                            responseData = $"{correctHeader}\n" + _data;
                                        }
                                        else {
                                            responseData = $"ERRORCODE[{(int)LoginErrorType.WrongPassword}]";
                                        }
                                    }
                                    else if (logintype == Logintype.EditAccount) {
                                        responseData = EditAccountData(name, hashPass, data) ? $"{correctHeader}\n" : $"ERRORCODE[{(int)LoginErrorType.WrongPassword}]";
                                    }

                                    response.ContentType = "text";
                                    response.StatusCode = 200;
                                    response.AppendHeader("access-control-expose-headers", "Content-Length, Date, Server, Transfer-Encoding, X-GUploader-UploadID, X-Google-Trace, origin, range");
                                    response.AppendHeader("access-control-allow-origin", "*");
                                    response.AppendHeader("accept-ranges", "bytes");
                                    if (request.HttpMethod == "OPTIONS") {
                                        response.AddHeader("Access-Control-Allow-Headers", "Content-Type, Accept, X-Requested-With");
                                        response.AddHeader("Access-Control-Allow-Methods", "GET, POST");
                                        response.AddHeader("Access-Control-Max-Age", "1728000");
                                    }

                                    // string responseString = SubData;
                                    byte[] buffer = System.Text.Encoding.UTF8.GetBytes(responseData);
                                    response.ContentLength64 = buffer.Length;
                                    using (var output = response.OutputStream) {
                                        output.Write(buffer, 0, buffer.Length);
                                    }
                                }
                                catch (Exception _ex) {
                                    Console.WriteLine(_ex);
                                }
                            }
                        }
                        else {
                            using (HttpListenerResponse response = context.Response) {
                                response.StatusCode = 500;
                                byte[] buffer = System.Text.Encoding.UTF8.GetBytes("Error");
                                response.ContentLength64 = buffer.Length;
                                using (var output = response.OutputStream) {
                                    output.Write(buffer, 0, buffer.Length);
                                }
                            }
                        }
                    }
                }
            }
            catch (Exception _ex) {
                Console.WriteLine("ERROR: " + _ex + "\nPress any key to exit");
                Console.ReadKey();
            }
        }
    }
}
