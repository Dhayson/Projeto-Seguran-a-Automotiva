import sys
import pandas

args = sys.argv

def convert_log_line(line: str, atk_line: str) -> tuple[bool, pandas.Series]:
    if line == "Created a socket" or line == "":
        return False, None
    
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
    
    is_atk = False
    
    if atk_line != "":
        atk_segments = atk_line.split(" ")
        atk_body = atk_segments[2]
        if atk_body == body:
            is_atk = True
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
        'Label' : "Attack" if is_atk else "Benign"
    }
    serie = pandas.Series(dir)
    return is_atk, serie

frame = pandas.DataFrame()
i = 0
with open(args[2], "r") as atk_log:
    with open(args[1], "r") as bus_log:
        bus_log = bus_log.read()
        atk_log = iter(atk_log.read().split("\n"))
        atk_line = next(atk_log)
        atk_line = next(atk_log)
        for line in bus_log.split("\n"):
            is_atk, conversion = convert_log_line(line, atk_line)
            if is_atk:
                print(f"\rAttacks: {i}", end="")
                atk_line = next(atk_log)
                i+=1
            if conversion is not None:
                new_row = pandas.DataFrame([conversion])
                frame = pandas.concat([frame, new_row], ignore_index=True)
print()
print(frame)
frame.to_csv(args[3])