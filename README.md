# VirusTotal-IP-report-automation  
Python automation for checking IP addresses in VirusTotal  
  
Most Linux distributions come with Python pre-installed. You can check if Python is installed by running:  
python3 --version  
If Python is not installed, you can install it using your package manager. For example, on Ubuntu, you can use:  
sudo apt update  
sudo apt install python3  
Install requests library:  
pip install requests  
  
Prepare a CSV file named destination_ips.csv with the list of IP addresses you want to analyze. The file should have one IP address per line.    
For example, if you use Splunk, you can filter for required IP output and download it as .csv file.  
A file with IP addresses should be in the same directory as Python script file.  
  
Sign up for a free VirusTotal account at virustotal.com and obtain your API key from your account settings.  
Replace the placeholder 'your_api_key_here' in the script with your actual VirusTotal API key.  
Save the script as ip_list.py and run it from your terminal or command prompt:  
python ip_list.py  
  
Results File: The results of the script execution will be printed to the console. If you wish to save the output to a file, you can redirect the output:  
python ip_list.py > results.txt  
  
All files should be kept in the same directory for ease of use.  
