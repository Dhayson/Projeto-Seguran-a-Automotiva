import can

# Configuração da interface CAN (can0 = exemplo)
bus = can.interface.Bus(channel='can0', bustype='socketcan')

def getMessageFromBus(bus):
    return next(bus)

def getFormattedMessage(bus):
    msg = getMessageFromBus(bus)
    payload = "".join(["{:02X}".format(byte) for byte in msg.data])
    return f'({msg.timestamp}) {msg.channel} {hex(msg.arbitration_id)}#{payload}'