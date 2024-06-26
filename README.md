# NetFlow

![Witcher-Logo-PNG-758x473-fotor-bg-remover-20240324133956](https://github.com/hoaxter/netflow/assets/141468297/69ccbda0-ca2d-48cd-b138-d2db5bf01ad8)

  This Python script utilizes Scapy for sniffing network packets and provides functionalities such as packet count alerts, packet counts by type, and the ability to change the interface for sniffing.
 
## Features

- Sniff network packets on a specified interface.
- Set alerts for packet counts exceeding a specified limit.
- Display packet counts by type.
- Change the interface for packet sniffing.
- Extract detailed information from sniffed packets.

## Installation

1. Clone the repository:

   ```
   git clone https://github.com/hoaxter/netflow.git
   ```
2. Open the directory
   ```
   cd netflow
   ```
3. Install the requirements
   ```
   pip install -r requirements.txt
   ```
4. Run the script
   ```
   python netflow.py
   ```
   ![Screenshot 2024-03-27 185913](https://github.com/hoaxter/netflow/assets/141468297/ed96a31c-00e1-4376-8b71-92e945f9b827)
   
   Choose options from the menu to perform various actions such as sniffing packets, setting alerts, displaying packet counts, etc.

## Configuration

- Modify the ports dictionary to add or remove ports of interest.
- Adjust the limit variable to set the threshold for packet count alerts.
- Change the iface variable to specify the network interface for packet sniffing.

## Menu Options

- Normal Sniff (Option 0): Sniff packets without setting any alerts.
- Alert Sniff (Option 1): Set alerts for packet counts exceeding a specified limit.
- Alert Packet Count (Option 2): Display packet counts by type.
- Packet Alert Limit (Option 3): Change the packet count limit for alerts.
- Change Interface (Option 4): Change the network interface for packet sniffing.
- Exit (Option 5): Quit the program.

## Contributing
   Contributions are welcome! If you find any issues or have suggestions for improvements, feel free to open an issue or submit a pull request.

## License
   This project is licensed under the GNU General Public License (GPL).
