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
            rsa = new RSACryptoServiceProvider(2048); //Generer RSA keypair med størrelse 2048 bit
            pubKey = rsa.ExportParameters(false); //Extracter public key
            string pubKeyString; //Vi laver public key om til en string
            {
                //Vi laver en stream at skrive den til
                var sw = new StringWriter();
                //Vi laver en serializer, som omdanner keyen til XML, og storer det i en string, så det kan sendes senere
                var xs = new System.Xml.Serialization.XmlSerializer(typeof(RSAParameters));
                xs.Serialize(sw, pubKey);
                pubKeyString = sw.ToString();
            }
            Console.WriteLine("Enter IP of custom server, or enter 0 for Public Server, 1 for loopback, or 2 for debug server");
            string serverIP = Console.ReadLine();
            //Forskellige IP'er brugt til debugging
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

            //Laver hash af rum og pass, så det ikke kan opsnappes
            string hash = MakeHash(rum+pass);

            //Starter thread, der håndterer at sende til clients
            Thread sender = new Thread(new ThreadStart(Sender));
            sender.Start();
            //Starter thread, der håndterer at lukke døde threads
            Thread killer = new Thread(new ThreadStart(ThreadKiller));
            killer.Start();

            while (true)
            {
                //If statement, der checker om der ønskes at starte en ny forbindelse. Ellers springer den koden over
                if (!cont)
                {
                    Thread.Sleep(10);
                    continue;
                }
                try
                {
                    //Initial forbindelse til server
                    TcpClient tcp = new TcpClient();
                    tcp.Connect(serverIP, 5050);
                    //Sender hashet af rum og pass
                    Send(tcp, hash);

                    //Venter på serveren sender go signalet, som signallerer at der klar til holepunching
                    while (true)
                    {
                        if (Read(tcp) == "!GO")
                        {
                            break;
                        }
                    }
                    //Starter forbindelse til at facilitate holepunching
                    Console.WriteLine("Establishing Connection");
                    tcp.Close();
                    TcpClient tcp2 = new TcpClient();
                    tcp2.Connect(serverIP, 5050 + 1);
                    //Lagrer midlertidligt IP og key, sendt i samme besked, i et variabel, der så splittes på kommaet der sepererer dem
                    string temp = Read(tcp2);
                    string peerIP = temp.Split(',')[0];
                    int port = Convert.ToInt32(temp.Split(',')[1]);
                    //Instantiater en ny instance af Client classen
                    Client client = new Client();
                    Console.WriteLine("Attempting Connection to {0} {1}", peerIP, port);
                    //Connecter til peer
                    client.client.ConnectAsync(peerIP, port + 1).Wait(2000);
                    //Opretter RSA instance til enkryption
                    client.csp = new RSACryptoServiceProvider();
                    //Sender public key
                    Send(client.client, pubKeyString);
                    //Modtager peer public key, og konverter til RSAParameters objekt, på samme måde som vi lavede en publicKeyString
                    RSAParameters newKey;
                    {
                        var sr = new StringReader(Read(client.client));
                        var xs = new System.Xml.Serialization.XmlSerializer(typeof(RSAParameters));
                        newKey = (RSAParameters)xs.Deserialize(sr);
                    }
                    //Importer public key til encrypter
                    client.csp.ImportParameters(newKey);
                    //Printer public key for #HackerVibes
                    Console.WriteLine("Public key received from {0}:{1}\nKey Lengt: {2}\nKey: {3}", peerIP, port, newKey.Modulus.Length*8, Convert.ToBase64String(newKey.Modulus));
                    //Sender brugernavn som en krypteret besked
                    eSend(client, user);
                    //Sætter brugernavn af peer
                    client.name = eRead(client);
                    //Starter og indstiller indstillinger for thread til at receive fra peer
                    Thread receiver = new Thread(() => Receive(client));
                    client.client.ReceiveTimeout = 1;
                    receiver.Start();
                    client.receiver = receiver;
                    //´Tilføjer clienten til listen af clients
                    clients.Add(client);
                    Console.WriteLine("Connected to {0}:{1} with name {2}", peerIP, port + 1, client.name);
                    //sørger for den ikke looper
                    cont = false;
                    //Console.WriteLine("Connected to {0}", client.name);
                }
                catch 
                {
                    //Skriver hvis der er en fejl
                    Console.WriteLine("Connection failed - retrying");
                }
            }
        }

        static void Send(TcpClient client, string msg)
        {
            //Omdanner message til et byte array, med UTF8 enkodning
            byte[] data = Encoding.UTF8.GetBytes(msg);
            //Skriver byte arrayet til networkstreamen
            client.GetStream().Write(data, 0, data.Length);
        }
        static string Read(TcpClient tcp)
        {
            //Gør en buffer klar, til at læse data
            Byte[] data = new Byte[4096];
            //Gør en string klar
            String responseData = String.Empty;
            //Læser bytesne, og lagrer mængden af bytes læst
            int bytes = tcp.GetStream().Read(data, 0, data.Length);
            //Konverterer til en string, og returnerer den
            return (Encoding.UTF8.GetString(data, 0, bytes));
        }
        static void eSend(Client client, string msg)
        {
            //Samme som send, men der krypteres med clients public key
            try
            {
                byte[] data = Encoding.UTF8.GetBytes(msg);
                byte[] dataCypherText = client.csp.Encrypt(data, true);
                client.client.GetStream().Write(dataCypherText, 0, dataCypherText.Length);
            }
            catch
            {
                Console.WriteLine("Failed to send message");
            }
        }
        static string eRead(Client tcp)
        {
            //Samme som read, men dekrypterer med personlig private key
            Byte[] data = new Byte[256];
            String responseData = String.Empty;
            int bytes = tcp.client.GetStream().Read(data, 0, data.Length);
            byte[] msg = rsa.Decrypt(data, true);
            return (Encoding.UTF8.GetString(msg));
        }
        //Startes som en thread i main
        static void Sender()
        {
            //While loop sørger for at threaden kører altid
            while (true)
            {
                string msg = Console.ReadLine(); //Læser besked fra konsol
                //Checker om det er en kommando
                if (msg == "!ADD")
                {
                    //Sætter conditional, så der oprettes en forbindelse til i main
                    cont = true;
                }
                else if (msg.Contains("!DISCONNECT"))
                {
                    Environment.Exit(0);
                }
                else {
                    //Sender til alle clients
                    foreach (var client in clients)
                    {
                        eSend(client, msg);
                    }
                }
            }
        }

        static void Receive(Client client)
        {
            while (client.client.Connected) {
                //Essentielt det samme som eRead
                Byte[] data = new Byte[256];
                String responseData = String.Empty;
                int bytes = 0;
                //Smider exceptions når readTimeout, som er en intended feature sker, thrower den en exception. Derfor skal være i et try.
                try
                {
                    bytes = client.client.GetStream().Read(data, 0, data.Length);
                    byte[] msg = rsa.Decrypt(data, true);
                    //Printer besked i stedet for at return
                    Console.WriteLine("{0}: {1}", client.name, Encoding.UTF8.GetString(msg));
                }
                catch { }
            }
        }

        //Laver hashen
        static string MakeHash(string input)
        {
            //Initialiser stream
            var memoryStream = new MemoryStream();
            var streamWriter = new StreamWriter(memoryStream, Encoding.UTF8);
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
                //Er i try, da hvis der er noget som skriver til listen samtidigt, thrower det en exception. Vi er lidt ligeglade, og kører det bare igen en anden gang

                /*foreach (var client in clients)
                {
                    //Tjekker om receiver threaden er i live
                    if (!client.receiver.IsAlive)
                    {
                        //Lukker threaden ordentlig
                        client.receiver.Join();
                        Console.WriteLine("{0} with IP {1} has disconnected", client.name, client.client.Client.RemoteEndPoint.ToString());
                        //Lukker clienten ordentlig
                        client.client.Close();
                        //Fjerne den fra listen
                        clients.Remove(client);
                    }
                }*/
                for (int i = 0; i < clients.Count; i++)
                {
                    // Tjekker om receiver threaden er i live
                    if (!clients[i].receiver.IsAlive)
                    {
                        //Lukker threaden ordentlig
                        clients[i].receiver.Join();
                        Console.WriteLine("{0} with IP {1} has disconnected", clients[i].name, clients[i].client.Client.RemoteEndPoint.ToString());
                        //Lukker clienten ordentlig
                        clients[i].client.Close();
                        //Fjerne den fra listen
                        clients.Remove(clients[i]);
                    }
                }
                Thread.Sleep(5);
            }
        }
    }
}
