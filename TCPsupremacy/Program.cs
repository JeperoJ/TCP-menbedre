using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Net.Sockets;
using System.Net;
using System.Threading;
using System.Security.Cryptography;
using System.IO;

namespace TCPsupremacy
{
       
    class Program
    {
        private static RSACryptoServiceProvider rsa;
        private static RSAParameters pubKey;
        private static List<Client> clients = new List<Client>();
        private static bool cont = true;
        static void Main(string[] args)
        {
            rsa = new RSACryptoServiceProvider(2048);
            pubKey = rsa.ExportParameters(false);
            string pubKeyString;
            {
                //we need some buffer
                var sw = new StringWriter();
                //we need a serializer
                var xs = new System.Xml.Serialization.XmlSerializer(typeof(RSAParameters));
                //serialize the key into the stream
                xs.Serialize(sw, pubKey);
                //get the string from the stream
                pubKeyString = sw.ToString();
            }
            Console.WriteLine("Enter IP of server, or enter 0 for Mads or 1 for loopback, or 2 for din lokale luder");
            string serverIP = Console.ReadLine();
            if (serverIP == "0")
            {
                serverIP = "176.23.96.141";
            }
            else if (serverIP == "1")
            {
                serverIP = "127.0.0.1";
            }
            else if (serverIP == "2")
            {
                serverIP = "10.146.75.224";
            }

            Console.Write("Room Name: ");
            string rum = Console.ReadLine();
            Console.Write("Room Password: ");
            string pass = Console.ReadLine();
            Console.Write("Username: ");
            string user = Console.ReadLine();
            if (user == "")
            {
                user = "anon";
            }

            
            string hash = MakeHash(rum+pass);
            

            Thread sender = new Thread(new ThreadStart(Sender));
            sender.Start();
            Thread killer = new Thread(new ThreadStart(ThreadKiller));
            killer.Start();

            Console.WriteLine("Connected - Waiting for friends...");

            while (true)
            {
                if (!cont)
                {
                    break;
                }
                try
                {
                    Console.WriteLine("Fed");
                    TcpClient tcp = new TcpClient();
                    tcp.Connect(serverIP, 5050);
                    Send(tcp, hash);
                    //Send(tcp, rum + pass);

                    while (true)
                    {
                        if (Read(tcp) == "!GO")
                        {
                            break;
                        }
                    }
                    Console.WriteLine("Friend found, establish connection");
                    tcp.Close();
                    TcpClient tcp2 = new TcpClient();
                    tcp2.Connect(serverIP, 5050 + 1);
                    string mesa = Read(tcp2);
                    Console.WriteLine(mesa);
                    string peerIP = mesa.Split(',')[0];
                    int port = Convert.ToInt32(mesa.Split(',')[1]);
                    Client client = new Client();
                    Console.WriteLine("Attempting Holepunch {0} {1}", peerIP, port);
                    client.client.ConnectAsync(peerIP, port + 1).Wait(2000);
                    Console.WriteLine("Penis");
                    client.csp = new RSACryptoServiceProvider();
                    Send(client.client, pubKeyString);
                    Console.WriteLine("lille håb");
                    RSAParameters newKey;
                    string newKeyString = Read(client.client);
                    Console.WriteLine(newKeyString);
                    {
                        //get a stream from the string
                        var sr = new StringReader(newKeyString);
                        Console.WriteLine("hhm");
                        //we need a deserializer
                        var xs = new System.Xml.Serialization.XmlSerializer(typeof(RSAParameters));
                        //get the object back from the stream
                        newKey = (RSAParameters)xs.Deserialize(sr);
                    }
                    Console.WriteLine("yeet");
                    client.csp.ImportParameters(newKey);
                    Console.WriteLine("Større penis");

                    eSend(client, user);
                    client.name = eRead(client);
                    Thread receiver = new Thread(() => Receive(client));
                    client.client.ReceiveTimeout = 1;
                    receiver.Start();
                    client.receiver = receiver;
                    clients.Add(client);
                    Console.WriteLine("Connected to {0}:{1} with name {2}", peerIP, port + 1, client.name);
                    cont = false;
                    //Console.WriteLine("Connected to {0}", client.name);
                }
                catch 
                {
                    Console.WriteLine("Holepunch virker ikke");
                }
            }
        }

        static void Send(TcpClient client, string msg)
        {
            byte[] data = Encoding.UTF8.GetBytes(msg);
            client.GetStream().Write(data, 0, data.Length);
        }
        static string Read(TcpClient tcp)
        {
            Byte[] data = new Byte[4096];
            String responseData = String.Empty;
            int bytes = tcp.GetStream().Read(data, 0, data.Length);
            return (Encoding.UTF8.GetString(data, 0, bytes));
        }
        static void eSend(Client client, string msg)
        {
            byte[] data = Encoding.UTF8.GetBytes(msg);
            byte[] dataCypherText = client.csp.Encrypt(data, true);
            client.client.GetStream().Write(dataCypherText, 0, dataCypherText.Length);
        }
        static string eRead(Client tcp)
        {
            Byte[] data = new Byte[256];
            String responseData = String.Empty;
            int bytes = tcp.client.GetStream().Read(data, 0, data.Length);
            byte[] msg = rsa.Decrypt(data, true);
            return (Encoding.UTF8.GetString(msg));
        }
        static void Sender()
        {
            while (true)
            {
                string msg = Console.ReadLine();
                if (msg == "!ADD")
                {
                    cont = true;
                    break;
                }
                foreach (var client in clients)
                {
                    eSend(client, msg);
                }
            }
        }

        static void Receive(Client client)
        {
            while (client.client.Connected) {
                Byte[] data = new Byte[256];
                String responseData = String.Empty;
                int bytes = 0;
                try
                {
                    bytes = client.client.GetStream().Read(data, 0, data.Length);
                    byte[] msg = rsa.Decrypt(data, true);
                    Console.WriteLine("{0}: {1}", client.name, Encoding.UTF8.GetString(msg));
                }
                catch { }
            }
        }

        static string MakeHash(string input)
        {
            //Initialiser stream
            var memoryStream = new MemoryStream();
            var streamWriter = new StreamWriter(memoryStream, Encoding.UTF8); //Skift encoding hvis det behøves
            //Skriv string til streamen
            streamWriter.Write(input);
            streamWriter.Flush();
            memoryStream.Position = 0;

            //Lav hashet
            string output = Encoding.UTF8.GetString(SHA256.Create().ComputeHash(memoryStream));
            return output;
        }

        static void ThreadKiller()
        {
            while (true)
            {
                try
                {
                    foreach (var client in clients)
                    {
                        if (!client.receiver.IsAlive)
                        {
                            client.receiver.Join();
                            Console.WriteLine("{0} has disconnected", client.client.Client.RemoteEndPoint.ToString());
                            client.client.Close();
                            clients.Remove(client);
                        }
                    }
                }
                catch { }
                Thread.Sleep(10);
            }
        }
    }
}
