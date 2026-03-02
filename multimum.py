import argparse
import subprocess
import threading
from queue import Queue

def run_command(ip, port, command_template):
    command = command_template.replace("IP", ip).replace("PORT", port)
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        # Print both stdout and stderr if they exist
        output = result.stdout
        if result.stderr:
            output += f"\nError: {result.stderr}"
        print(f"----------------------------------------------------------------")
        print(f"Output for {ip}:{port}:\n{output}")
        #print(f"-----------------------------------------------------------")
    except subprocess.CalledProcessError as e:
        print(f"Error executing command on {ip}:{port}:\n{e}")
        print(f"----------------------------------------------------------------")

def worker(queue, command_template):
    while not queue.empty():
        ip, port = queue.get()
        run_command(ip, port, command_template)
        queue.task_done()

def main():
    parser = argparse.ArgumentParser(description='Run command on IP:PORT pairs from a file.')
    parser.add_argument('-l', '--list', required=True, help='Path to the file containing IP:PORT pairs.')
    parser.add_argument('-c', '--command', required=True, help='Command template to run. Use "IP" and "PORT" as placeholders.')
    parser.add_argument('-t', '--threads', type=int, default=4, help='Number of concurrent threads to use (default: 4).')

    args = parser.parse_args()

    with open(args.list, 'r') as f:
        lines = f.readlines()

    queue = Queue()

    for line in lines:
        line = line.strip()
        if ':' in line:
            ip, port = line.split(':')
            queue.put((ip, port))
        else:
            print(f"Skipping invalid line: {line}")

    threads = []
    for _ in range(args.threads):
        thread = threading.Thread(target=worker, args=(queue, args.command))
        thread.start()
        threads.append(thread)

    queue.join()

    for thread in threads:
        thread.join()

if __name__ == "__main__":
    main()
