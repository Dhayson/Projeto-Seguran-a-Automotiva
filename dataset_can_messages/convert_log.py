import sys
import pandas

args = sys.argv

def convert_log_line(line: str):
    if line == "Created a socket" or line == "":
        return None
    segments = line.split(" ")
    timestamp = float(segments[0][1:-1])
    body = segments[2]
    body_parts = body.split("#")
    id = int(body_parts[0], 16)
    data = body_parts[1]
    data_bytes = []
    if data == "0" or data == "":
        # Zera os data bytes para mensagens sem dados
        data_bytes = [0]*7
    else:
        for i in range(0, len(data), 2):
            data_bytes.append(int(f"0x{data[i:i+2]}",16))
        
    dir = {
        'timestamp': timestamp,
        'authentication_id': id,
        'data_0': data_bytes[0],
        'data_1': data_bytes[1],
        'data_2': data_bytes[2],
        'data_3': data_bytes[3],
        'data_4': data_bytes[4],
        'data_5': data_bytes[5],
        'data_6': data_bytes[6],
        'Label': "Benign"
    }
    serie = pandas.Series(dir)
    return serie

frame = pandas.DataFrame()
with open(args[1], "r") as log:
    log = log.read()
    for line in log.split("\n"):
        conversion = convert_log_line(line)
        if conversion is not None:
            new_row = pandas.DataFrame([conversion])
            frame = pandas.concat([frame, new_row], ignore_index=True)
print(frame)
frame.to_csv(args[2])