from flowstat import PacketCapture

from pathlib import Path
import signal
import sys
import os

if len(sys.argv) != 2:
    print("Script needs exactly one argument.")
    exit(1)


path = Path(sys.argv[1])

if not path.exists():
    print("Path {} does not exist".format(path))
    exit(2)


def process_folder(folder_path:Path):
    for current_file in os.listdir(folder_path):
        current_path = Path(folder_path.joinpath(current_file))
        if current_path.is_dir():
            process_folder(current_path.absolute()) 
        elif current_path.is_file() and (".pcap" in str(current_path.absolute())):
            print("Processing pcap file {}".format(current_path.absolute()))
            cap = PacketCapture(str(current_path.absolute()))
            cap.set_print_flow_table(False)
            def signal_handler(sig, frame):
                print('You pressed Ctrl+C!')
                try:
                    cap.stop()
                except:
                    exit(0)
            signal.signal(signal.SIGINT, signal_handler)
            cap.run()
            cap.stop()


if path.is_file() and ".pcap" in str(path.absolute()):

    cap = PacketCapture(sys.argv[1])
    cap.set_print_flow_table(False)
    def signal_handler(sig, frame):
        print('You pressed Ctrl+C!')
        try:
            cap.stop()
        except:
            exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    cap.run()

elif path.is_dir():
    process_folder(path.absolute())
else:
    print("Given file is not a pcap file nor folder.")





